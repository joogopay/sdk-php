<?php

declare(strict_types=1);

/**
 * Protocol vector and client tests.
 *
 * No PHPUnit: the SDK ships with zero third-party dependencies, tests included.
 * Run: php tests/run.php
 *   or docker run --rm -v "$PWD":/app -w /app php:8.3-cli php tests/run.php
 */

require __DIR__ . '/autoload.php';
require __DIR__ . '/../src/Exceptions.php';
require __DIR__ . '/../src/Protocol.php';
require __DIR__ . '/../src/Status.php';
require __DIR__ . '/../src/Rules.php';
require __DIR__ . '/../src/Client.php';

use Joogopay\Sdk\ApiException;
use Joogopay\Sdk\Client;
use Joogopay\Sdk\ConfigException;
use Joogopay\Sdk\ExpiredSignatureException;
use Joogopay\Sdk\InvalidEnvelopeException;
use Joogopay\Sdk\InvalidHeaderException;
use Joogopay\Sdk\InvalidSignatureException;
use Joogopay\Sdk\Protocol as P;
use Joogopay\Sdk\RequestException;
use Joogopay\Sdk\ResponseException;
use Joogopay\Sdk\Status;
use Joogopay\Sdk\TransportException;
use Joogopay\Sdk\WebhookException;

$passed = 0;
$failed = [];

function test(string $name, callable $fn): void
{
    global $passed, $failed;
    try {
        $fn();
        $passed++;
    } catch (\Throwable $e) {
        $failed[] = "{$name}\n      " . $e->getMessage();
    }
}

function eq(mixed $got, mixed $want, string $hint = ''): void
{
    if ($got !== $want) {
        throw new \AssertionError(
            ($hint !== '' ? "{$hint}: " : '')
            . 'got ' . var_export($got, true) . ', want ' . var_export($want, true)
        );
    }
}

function ok(bool $cond, string $hint = ''): void
{
    if (!$cond) {
        throw new \AssertionError($hint !== '' ? $hint : 'expected true');
    }
}

function throws(string $class, callable $fn, string $hint = ''): void
{
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($e instanceof $class) {
            return;
        }
        throw new \AssertionError(
            ($hint !== '' ? "{$hint}: " : '') . 'expected ' . $class . ', got ' . $e::class
        );
    }
    throw new \AssertionError(($hint !== '' ? "{$hint}: " : '') . "expected {$class}, nothing thrown");
}

define('TESTDATA', dirname(__DIR__) . '/protocol/testdata');

function load(string $rel): array
{
    return json_decode(file_get_contents(TESTDATA . '/' . $rel), true, 512, JSON_THROW_ON_ERROR);
}

$SIG_READ = load('signature/001-read-query.json');
$SIG_WRITE = load('signature/002-write-envelope.json');
$SIG_RAW_QUERY = load('signature/003-read-raw-query-unicode.json');
$BODY = load('bodycrypt/001-sealed-box.json');
$EMPTY_POST = load('empty-object-post/001-empty-object.json');
$HOOK = load('webhook/001-payment-succeeded.json');

/** Recovers the header map from expected.signatureBase so the tests never fabricate inputs. */
function headersFromBase(string $signatureBase): array
{
    $names = [
        'content-type' => 'Content-Type',
        'content-encryption' => P::HEADER_CONTENT_ENCRYPTION,
        'content-digest' => P::HEADER_CONTENT_DIGEST,
        'idempotency-key' => P::HEADER_IDEMPOTENCY_KEY,
        'merchant-access-key' => P::HEADER_MERCHANT_ACCESS_KEY,
        'webhook-event-id' => P::HEADER_WEBHOOK_EVENT_ID,
    ];
    $headers = [];
    foreach (explode("\n", $signatureBase) as $line) {
        $idx = strpos($line, ': ');
        if ($idx === false) {
            continue;
        }
        $key = json_decode(substr($line, 0, $idx), true);
        if (isset($names[$key])) {
            $headers[$names[$key]] = substr($line, $idx + 2);
        }
    }
    return $headers;
}

foreach ([
    ['signature/001-read-query.json', P::MERCHANT_READ_COVERED, $SIG_READ],
    ['signature/002-write-envelope.json', P::MERCHANT_WRITE_COVERED, $SIG_WRITE],
    ['signature/003-read-raw-query-unicode.json', P::MERCHANT_READ_COVERED, $SIG_RAW_QUERY],
] as [$name, $covered, $v]) {
    test("signature vector matches byte for byte: {$name}", function () use ($covered, $v) {
        $params = [
            'label' => P::SIGNATURE_LABEL_MERCHANT,
            'covered' => $covered,
            'created' => 1787803200,
            'expires' => 1787803500,
            'nonce' => $v['input']['nonce'],
            'keyId' => '',
            'alg' => P::SIGNATURE_ALG_ED25519,
        ];

        $gotInput = P::signatureInputHeader($params);
        eq($gotInput, $v['expected']['signatureInput'], 'Signature-Input');
        ok(!str_contains($gotInput, 'keyid'), 'merchant requests must not carry keyid');

        $base = P::signatureBase(
            $params,
            $v['input']['method'],
            $v['input']['path'],
            $v['input']['rawQuery'],
            headersFromBase($v['expected']['signatureBase'])
        );
        eq($base, $v['expected']['signatureBase'], 'signature base');

        // Ed25519 is deterministic, so the signature compares byte for byte
        $signature = P::signEd25519(
            base64_decode($v['key']['merchantPrivateKeyBase64']),
            P::SIGNATURE_LABEL_MERCHANT,
            $base
        );
        eq($signature, $v['expected']['signature'], 'signature');

        P::verifyEd25519(
            base64_decode($v['key']['merchantPublicKeyBase64']),
            $base,
            P::parseSignature($v['expected']['signature'], P::SIGNATURE_LABEL_MERCHANT)
        );
    });
}

// A 32-byte seed and the 64-byte secret key must sign identically: libsodium and OpenSSL
// hand merchants the seed, while the vectors carry 64-byte keys, so nothing else covers it.
foreach ([
    ['signature/001-read-query.json', P::MERCHANT_READ_COVERED, $SIG_READ],
    ['signature/002-write-envelope.json', P::MERCHANT_WRITE_COVERED, $SIG_WRITE],
] as [$name, $covered, $v]) {
    test("32-byte seed and full private key sign identically: {$name}", function () use ($covered, $v) {
        $seed = base64_decode($v['key']['merchantPrivateKeySeedBase64']);
        $full = base64_decode($v['key']['merchantPrivateKeyBase64']);
        eq(strlen($seed), SODIUM_CRYPTO_SIGN_SEEDBYTES, 'seed length');
        eq(strlen($full), SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'full private key length');
        eq(substr($full, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES), $seed, 'seed is the first 32 bytes of the full key');

        $params = [
            'label' => P::SIGNATURE_LABEL_MERCHANT,
            'covered' => $covered,
            'created' => 1787803200,
            'expires' => 1787803500,
            'nonce' => $v['input']['nonce'],
            'keyId' => '',
            'alg' => P::SIGNATURE_ALG_ED25519,
        ];
        $base = P::signatureBase(
            $params,
            $v['input']['method'],
            $v['input']['path'],
            $v['input']['rawQuery'],
            headersFromBase($v['expected']['signatureBase'])
        );
        foreach ([$seed, $full] as $key) {
            eq(
                P::signEd25519($key, P::SIGNATURE_LABEL_MERCHANT, $base),
                $v['expected']['signature'],
                'both key forms sign identically'
            );
        }
    });
}

test('Client accepts both a 32-byte seed and a 64-byte private key', function () use ($SIG_READ) {
    foreach ([
        $SIG_READ['key']['merchantPrivateKeySeedBase64'],
        $SIG_READ['key']['merchantPrivateKeyBase64'],
    ] as $key) {
        new Client([
            'baseUrl' => 'https://api.example.com',
            'accessKey' => $SIG_READ['input']['accessKey'],
            'merchantPrivateKeyBase64' => $key,
            'platformBodyKeyId' => 'bodykey_1',
            'platformBodyPublicKeyBase64' => base64_encode(str_repeat("\0", 32)),
            'platformWebhookPublicKeys' => ['whk_1' => $SIG_READ['key']['merchantPublicKeyBase64']],
        ]);
    }
});

test('Signature-Input round-trips through parse and format', function () use ($SIG_READ) {
    $params = P::parseMerchantReadSignatureInput($SIG_READ['expected']['signatureInput']);
    eq($params['nonce'], $SIG_READ['input']['nonce']);
    eq($params['keyId'], '', 'merchant side carries no keyId');
    eq(P::signatureInputHeader($params), $SIG_READ['expected']['signatureInput']);
});

test('merchant Signature-Input rejects keyid', function () use ($SIG_READ) {
    $tampered = str_replace(
        ';alg="ed25519"',
        ';keyid="mkey_x";alg="ed25519"',
        $SIG_READ['expected']['signatureInput']
    );
    throws(InvalidHeaderException::class, fn () => P::parseMerchantReadSignatureInput($tampered));
});

test('body vector: decrypts to the expected plaintext', function () use ($BODY) {
    $wire = json_encode($BODY['envelope'], JSON_UNESCAPED_SLASHES);
    eq(P::peekBodyEnvelopeKeyId($wire), $BODY['keyId']);

    [$plaintext, $keyId] = P::openBodyEnvelope(
        $wire,
        base64_decode($BODY['platformBodyPublicKeyBase64']),
        base64_decode($BODY['platformBodyPrivateKeyBase64'])
    );
    eq($plaintext, base64_decode($BODY['plaintextBase64']));
    eq($keyId, $BODY['keyId']);
    throws(
        InvalidEnvelopeException::class,
        fn () => P::openBodyEnvelope($wire, str_repeat("\x44", 32), str_repeat("\x44", 32))
    );

    $tamperedCiphertext = base64_decode($BODY['envelope']['ciphertext']);
    $last = strlen($tamperedCiphertext) - 1;
    $tamperedCiphertext[$last] = chr(ord($tamperedCiphertext[$last]) ^ 0x01);
    $tamperedEnvelope = $BODY['envelope'];
    $tamperedEnvelope['ciphertext'] = base64_encode($tamperedCiphertext);
    $tamperedWire = json_encode($tamperedEnvelope, JSON_UNESCAPED_SLASHES);
    throws(InvalidEnvelopeException::class, fn () => P::openBodyEnvelope(
        $tamperedWire,
        base64_decode($BODY['platformBodyPublicKeyBase64']),
        base64_decode($BODY['platformBodyPrivateKeyBase64'])
    ));
});

test('body round trip: sealed-box ciphertext is nondeterministic, only a round trip can be checked', function () use ($BODY) {
    $plaintext = base64_decode($BODY['plaintextBase64']);
    $wire = P::sealBodyEnvelope(
        $plaintext,
        base64_decode($BODY['platformBodyPublicKeyBase64']),
        $BODY['keyId']
    );
    $envelope = json_decode($wire, true);
    eq($envelope['version'], 1);
    eq($envelope['alg'], P::CONTENT_ENCRYPTION);
    eq($envelope['keyId'], $BODY['keyId']);

    [$got, $keyId] = P::openBodyEnvelope(
        $wire,
        base64_decode($BODY['platformBodyPublicKeyBase64']),
        base64_decode($BODY['platformBodyPrivateKeyBase64'])
    );
    eq($got, $plaintext);
    eq($keyId, $BODY['keyId']);
});

test('envelope rejects algorithm drift and extra fields', function () use ($BODY) {
    $wrongAlg = json_encode(['alg' => 'aes-gcm'] + $BODY['envelope'], JSON_UNESCAPED_SLASHES);
    throws(InvalidEnvelopeException::class, fn () => P::decodeBodyEnvelope($wrongAlg));

    $extra = json_encode($BODY['envelope'] + ['unexpected' => 'x'], JSON_UNESCAPED_SLASHES);
    throws(InvalidEnvelopeException::class, fn () => P::decodeBodyEnvelope($extra));
});

test('empty-object POST vector: encryption, digest and signature match byte for byte', function () use ($EMPTY_POST) {
    $wire = json_encode($EMPTY_POST['envelope'], JSON_UNESCAPED_SLASHES);
    $bodyKey = $EMPTY_POST['platformBodyKey'];
    eq($EMPTY_POST['plaintext'], '{}');
    eq(P::contentDigestSha256($wire), $EMPTY_POST['expected']['contentDigest']);

    [$plaintext, $keyId] = P::openBodyEnvelope(
        $wire,
        base64_decode($bodyKey['publicKeyBase64']),
        base64_decode($bodyKey['privateKeyBase64'])
    );
    eq($plaintext, '{}');
    eq($keyId, $bodyKey['keyId']);

    $params = [
        'label' => P::SIGNATURE_LABEL_MERCHANT,
        'covered' => P::MERCHANT_WRITE_COVERED,
        'created' => 1787803200,
        'expires' => 1787803500,
        'nonce' => $EMPTY_POST['input']['nonce'],
        'keyId' => '',
        'alg' => P::SIGNATURE_ALG_ED25519,
    ];
    eq(P::signatureInputHeader($params), $EMPTY_POST['expected']['signatureInput']);
    $base = P::signatureBase(
        $params,
        $EMPTY_POST['input']['method'],
        $EMPTY_POST['input']['path'],
        $EMPTY_POST['input']['rawQuery'],
        headersFromBase($EMPTY_POST['expected']['signatureBase'])
    );
    eq($base, $EMPTY_POST['expected']['signatureBase']);
    eq(
        P::signEd25519(
            base64_decode($EMPTY_POST['merchantKey']['merchantPrivateKeyBase64']),
            P::SIGNATURE_LABEL_MERCHANT,
            $base
        ),
        $EMPTY_POST['expected']['signature']
    );
    throws(
        InvalidEnvelopeException::class,
        fn () => P::sealBodyEnvelope('', base64_decode($bodyKey['publicKeyBase64']), $bodyKey['keyId'])
    );
});

test('webhook vector: signature base matches and the signature verifies', function () use ($HOOK) {
    $body = $HOOK['body'];
    $headers = $HOOK['headers'];

    eq(P::contentDigestSha256($body), $headers['Content-Digest']);
    ok(P::verifyContentDigest($body, $headers['Content-Digest']));

    $params = P::parsePlatformSignatureInput($headers['Signature-Input']);
    eq($params['keyId'], $HOOK['key']['platformWebhookKeyId'], 'platform side keeps keyId');

    $base = P::signatureBase(
        $params,
        $HOOK['input']['method'],
        $HOOK['input']['path'],
        $HOOK['input']['rawQuery'],
        $headers
    );
    eq($base, $HOOK['expected']['signatureBase'], 'webhook signature base');

    P::verifyEd25519(
        base64_decode($HOOK['key']['platformWebhookPublicKeyBase64']),
        $base,
        P::parseSignature($headers['Signature'], P::SIGNATURE_LABEL_PLATFORM)
    );
    throws(InvalidSignatureException::class, fn () => P::verifyEd25519(
        str_repeat("\x55", 32),
        $base,
        P::parseSignature($headers['Signature'], P::SIGNATURE_LABEL_PLATFORM)
    ));

    P::validateWebhookEventId($headers['Webhook-Event-Id']);
    eq(json_decode($body, true)['eventId'], $headers['Webhook-Event-Id']);
});

test('webhook rejects a tampered amount', function () use ($HOOK) {
    $headers = $HOOK['headers'];
    $params = P::parsePlatformSignatureInput($headers['Signature-Input']);
    $tampered = str_replace('"100.50"', '"999.00"', $HOOK['body']);

    ok(!P::verifyContentDigest($tampered, $headers['Content-Digest']));

    $base = P::signatureBase(
        $params,
        $HOOK['input']['method'],
        $HOOK['input']['path'],
        $HOOK['input']['rawQuery'],
        ['Content-Digest' => P::contentDigestSha256($tampered)] + $headers
    );
    throws(InvalidSignatureException::class, fn () => P::verifyEd25519(
        base64_decode($HOOK['key']['platformWebhookPublicKeyBase64']),
        $base,
        P::parseSignature($headers['Signature'], P::SIGNATURE_LABEL_PLATFORM)
    ));
});

test('UUID v4 rules', function () {
    ok(P::validUuidV4('b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a'));
    ok(P::validUuidV4(P::newNonce()));
    ok(!P::validUuidV4('B7754A6C-4A9C-4CF0-B77F-6F2D4B7E5F5A'), 'must be lowercase');
    ok(!P::validUuidV4('b7754a6c-4a9c-1cf0-b77f-6f2d4b7e5f5a'), 'version nibble must be 4');
    ok(!P::validUuidV4('b7754a6c-4a9c-4cf0-c77f-6f2d4b7e5f5a'), 'variant must be 8/9/a/b');
});

test('webhook event id rules', function () {
    P::validateWebhookEventId('evt_00000000000000000000000001');
    foreach (['evt_0000', 'xxx_00000000000000000000000001', 'evt_0000000000000000000000000I'] as $bad) {
        throws(InvalidHeaderException::class, fn () => P::validateWebhookEventId($bad), $bad);
    }
});

test('GET query allowlist', function () {
    P::validateMerchantReadQuery('orderNo=P202608270001');
    P::validateMerchantReadQuery('currency=BRL&payMethod=PIX');
    foreach (['secret=1', 'orderNo=', 'orderNo=a&orderNo=b', 'orderNo=%zz'] as $bad) {
        throws(InvalidHeaderException::class, fn () => P::validateMerchantReadQuery($bad), $bad);
    }
});

test('signature time window', function () {
    $params = P::newMerchantReadSignatureParams(P::newNonce(), 1787803200);
    eq($params['expires'] - $params['created'], P::MAX_SIGNATURE_LIFETIME);
    P::validateFreshness($params, 1787803200);
    P::validateFreshness($params, 1787803500);
    throws(ExpiredSignatureException::class, fn () => P::validateFreshness($params, 1787803501));
    throws(
        ExpiredSignatureException::class,
        fn () => P::validateFreshness($params, 1787803200 - P::MAX_SIGNATURE_LIFETIME - 1)
    );
});

/** @var array<string,mixed> $captured */
$captured = [];
$nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{}}'];

$transport = function (string $url, string $method, array $headers, ?string $body) use (
    &$captured,
    &$nextResponse
): array {
    $captured = compact('url', 'method', 'headers', 'body');
    return [$nextResponse['status'], $nextResponse['body']];
};

function makeClient(callable $transport, array $overrides = []): Client
{
    global $SIG_READ, $BODY, $HOOK;
    return new Client(array_merge([
        'baseUrl' => 'https://api.example.com',
        'accessKey' => 'mak_live_test',
        'merchantPrivateKeyBase64' => $SIG_READ['key']['merchantPrivateKeyBase64'],
        'platformBodyKeyId' => $BODY['keyId'],
        'platformBodyPublicKeyBase64' => $BODY['platformBodyPublicKeyBase64'],
        'platformWebhookPublicKeys' => [
            $HOOK['key']['platformWebhookKeyId'] => $HOOK['key']['platformWebhookPublicKeyBase64'],
        ],
        'transport' => $transport,
    ], $overrides));
}

test('unencodable request body is a RequestException, never a TransportException', function () {
    $client = makeClient(fn () => throw new RuntimeException('must not be reached'));
    try {
        $client->createPayment([
            'merchantOrderNo' => 'M1', 'currency' => 'BRL', 'amount' => '1.00',
            'paymentMethod' => ['code' => 'PIX', 'pix' => ['payerName' => "\xB1\x31"]],
            'webhookUrl' => 'https://merchant.example/webhook',
        ]);
        ok(false, 'expected RequestException');
    } catch (RequestException $e) {
        ok(!($e instanceof TransportException), 'encoding failure is not a transport error');
    }
});

test('transport failure is a TransportException, never a RequestException', function () {
    $client = makeClient(fn () => [200, ''], ['transport' => null, 'baseUrl' => 'https://127.0.0.1:9', 'timeout' => 2]);
    try {
        $client->getBalance('BRL');
        ok(false, 'expected TransportException');
    } catch (TransportException $e) {
        ok(!($e instanceof RequestException), 'transport failure is not a request error');
    }
});

test('createPayment: wire shape and server-side decryption round trip', function () use ($transport, &$captured, &$nextResponse, $BODY) {
    $nextResponse = [
        'status' => 200,
        'body' => json_encode(['code' => 200, 'msg' => 'OK', 'data' => [
            'orderNo' => 'ORD001', 'status' => 'PENDING', 'amount' => '100.00', 'currency' => 'BRL',
        ]]),
    ];
    $order = makeClient($transport)->createPayment([
        'merchantOrderNo' => 'M202608270001',
        'currency' => 'BRL',
        'amount' => '100.00',
        'paymentMethod' => ['code' => 'PIX', 'pix' => ['payerCPF' => '12345678901']],
        'webhookUrl' => 'https://merchant.example.com/webhook/payments',
    ]);
    eq($order['orderNo'], 'ORD001');
    eq($order['amount'], '100.00', 'amount is a decimal string');

    $h = array_change_key_case($captured['headers']);
    eq($captured['method'], 'POST');
    ok(!str_contains($captured['url'], '?'), 'POST carries no query');
    eq($h['content-type'], 'application/json');
    eq($h['content-encryption'], P::CONTENT_ENCRYPTION);
    ok(P::validUuidV4($h['idempotency-key']));
    eq($h['merchant-access-key'], 'mak_live_test');
    ok(str_starts_with($h['signature-input'], 'merchant=('));
    ok(!str_contains($h['signature-input'], 'keyid'), 'merchant requests carry no keyId');
    ok(str_starts_with($h['signature'], 'merchant=:'));

    eq($h['content-digest'], P::contentDigestSha256($captured['body']), 'digest is computed over the envelope');
    $envelope = json_decode($captured['body'], true);
    eq($envelope['alg'], P::CONTENT_ENCRYPTION);
    eq($envelope['keyId'], $BODY['keyId']);

    [$plaintext, $keyId] = P::openBodyEnvelope(
        $captured['body'],
        base64_decode($BODY['platformBodyPublicKeyBase64']),
        base64_decode($BODY['platformBodyPrivateKeyBase64'])
    );
    eq($keyId, $BODY['keyId']);
    eq(json_decode($plaintext, true), [
        'merchantOrderNo' => 'M202608270001',
        'currency' => 'BRL',
        'amount' => '100.00',
        'paymentMethod' => ['code' => 'PIX', 'pix' => ['payerCPF' => '12345678901']],
        'webhookUrl' => 'https://merchant.example.com/webhook/payments',
    ]);
});

test('idempotency key can be reused for retries', function () use ($transport, &$captured) {
    $client = makeClient($transport);
    $key = P::newNonce();
    $req = [
        'merchantOrderNo' => 'M1', 'currency' => 'BRL', 'amount' => '1.00',
        'payoutMethod' => ['code' => 'PIX', 'pix' => ['keyType' => 'CPF', 'key' => '12345678901']], 'webhookUrl' => 'https://m.example.com/w',
    ];
    $client->createPayout($req, $key);
    $first = array_change_key_case($captured['headers'])['idempotency-key'];
    $client->createPayout($req, $key);
    eq($first, $key);
    eq(array_change_key_case($captured['headers'])['idempotency-key'], $key);
});

test('query: GET has no body and no write-only headers', function () use ($transport, &$captured, &$nextResponse) {
    $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{"orderNo":"ORD001"}}'];
    makeClient($transport)->queryPaymentByOrderNo('P202608270001');

    $h = array_change_key_case($captured['headers']);
    eq($captured['method'], 'GET');
    eq($captured['url'], 'https://api.example.com/api/v1/payments?orderNo=P202608270001');
    eq($captured['body'], null, 'GET has no body');
    foreach (['content-type', 'content-encryption', 'content-digest', 'idempotency-key'] as $absent) {
        ok(!isset($h[$absent]), "GET must not carry {$absent}");
    }
    ok(!str_contains($h['signature-input'], 'keyid'));
});

test('query: blank query parameter is rejected', function () use ($transport) {
    throws(RequestException::class, fn () => makeClient($transport)->queryPaymentByOrderNo('   '));
});

test('balance and USD rate use the current paths, not the legacy ones', function () use ($transport, &$captured, &$nextResponse) {
    $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{"balance":"10.00"}}'];
    makeClient($transport)->getBalance('BRL');
    ok(str_contains($captured['url'], '/api/v1/balances?'), 'not the legacy /merchant/balance');

    $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{"usdRate":"5.40"}}'];
    $rate = makeClient($transport)->getUsdRate('BRL', 'PIX');
    ok(str_contains($captured['url'], '/api/v1/usd-rates?'), 'not the legacy /payment/usdRate');
    eq($rate['usdRate'], '5.40');
});

test('receipt: path parameter is escaped and no query is sent', function () use ($transport, &$captured, &$nextResponse) {
    $nextResponse = [
        'status' => 200,
        'body' => '{"code":200,"msg":"OK","data":{"orderNo":"ORD/001","amount":"100.00"}}',
    ];
    $receipt = makeClient($transport)->getPayoutReceipt('ORD/001');
    eq($captured['url'], 'https://api.example.com/api/v1/payouts/ORD%2F001/receipt');
    ok(!str_contains($captured['url'], '?'));
    eq($receipt['amount'], '100.00');
});

test('receipt: empty order number is rejected', function () use ($transport) {
    throws(RequestException::class, fn () => makeClient($transport)->getPayoutReceipt(''));
});

test('response vector 001: success', function () use ($transport, &$nextResponse) {
    $v = load('responses/001-success-payment-order.json');
    $nextResponse = ['status' => $v['httpStatus'], 'body' => json_encode($v['body'])];
    $order = makeClient($transport)->queryPaymentByOrderNo('ORD202605190001');
    eq($order['orderNo'], 'ORD202605190001');
    eq($order['status'], Status::SUCCEEDED);
    eq($order['action']['qrCode'], '00020-qr');
});

test('response vector 002: business error becomes ApiException', function () use ($transport, &$nextResponse) {
    $v = load('responses/002-api-error-order-not-found.json');
    $nextResponse = ['status' => $v['httpStatus'], 'body' => json_encode($v['body'])];
    try {
        makeClient($transport)->queryPaymentByOrderNo('missing');
        throw new \AssertionError('expected ApiException');
    } catch (ApiException $e) {
        eq($e->httpStatus, $v['expectedFields']['HTTPStatus']);
        eq($e->getCode(), $v['expectedFields']['Code']);
        eq($e->msg, $v['expectedFields']['Msg']);
        eq($e->apiMessage, $v['expectedFields']['Message']);
        eq($e->traceId, $v['expectedFields']['TraceID']);
    }
});

test('response vector 003: HTTP 200 with a non-200 envelope code still fails', function () use ($transport, &$nextResponse) {
    $v = load('responses/003-http-200-envcode-not-ok.json');
    $nextResponse = ['status' => $v['httpStatus'], 'body' => json_encode($v['body'])];
    try {
        makeClient($transport)->queryPaymentByOrderNo('drift');
        throw new \AssertionError('expected ApiException');
    } catch (ApiException $e) {
        eq($e->httpStatus, 200);
        eq($e->getCode(), 12100099);
    }
});

// An order array with no orderNo would be recorded as a successful payout.
test('a success envelope without data is a ResponseException', function () use ($transport, &$nextResponse) {
    $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":null}'];
    throws(ResponseException::class, fn () => makeClient($transport)->queryPaymentByOrderNo('P1'));
});

test('response vector 004: non-JSON response becomes ResponseException', function () use ($transport, &$nextResponse) {
    $v = load('responses/004-non-json-body.json');
    $nextResponse = [
        'status' => $v['httpStatus'],
        'body' => file_get_contents(TESTDATA . '/responses/' . $v['bodyFile']),
    ];
    try {
        makeClient($transport)->queryPaymentByOrderNo('boom');
        throw new \AssertionError('expected ResponseException');
    } catch (ResponseException $e) {
        eq($e->httpStatus, $v['expectedFields']['HTTPStatus']);
    }
});

test('response vector money fields are decimal strings', function () {
    foreach (glob(TESTDATA . '/responses/*.json') as $path) {
        $data = json_decode(file_get_contents($path), true)['body']['data'] ?? null;
        if (!is_array($data)) {
            continue;
        }
        foreach (Status::MONEY_FIELDS as $field) {
            if (array_key_exists($field, $data)) {
                ok(
                    is_string($data[$field]),
                    basename($path) . ": {$field}=" . var_export($data[$field], true)
                    . ' must be a decimal string'
                );
            }
        }
    }
});

test('parses a payment webhook', function () use ($transport, $HOOK) {
    $hook = makeClient($transport, ['now' => fn () => 1787803300])->parsePaymentWebhook(
        $HOOK['input']['method'],
        $HOOK['input']['path'],
        $HOOK['headers'],
        $HOOK['body'],
        $HOOK['input']['rawQuery']
    );
    eq($hook['eventId'], $HOOK['headers']['Webhook-Event-Id']);
    eq($hook['orderType'], 'PAYMENT');
    eq($hook['status'], Status::SUCCEEDED);
    eq($hook['amount'], '100.50');
    eq($hook['paidAmount'], '100.50');
});

test('webhook rejects an unknown keyId', function () use ($transport, $HOOK) {
    $client = makeClient($transport, [
        'now' => fn () => 1787803300,
        'platformWebhookPublicKeys' => [
            'wk_other' => $HOOK['key']['platformWebhookPublicKeyBase64'],
        ],
    ]);
    throws(WebhookException::class, fn () => $client->parsePaymentWebhook(
        $HOOK['input']['method'],
        $HOOK['input']['path'],
        $HOOK['headers'],
        $HOOK['body'],
        $HOOK['input']['rawQuery']
    ));
});

test('webhook rejects an expired signature', function () use ($transport, $HOOK) {
    throws(
        ExpiredSignatureException::class,
        fn () => makeClient($transport, ['now' => fn () => 1787803501])->parsePaymentWebhook(
            $HOOK['input']['method'],
            $HOOK['input']['path'],
            $HOOK['headers'],
            $HOOK['body'],
            $HOOK['input']['rawQuery']
        )
    );
});

test('webhook rejects a mismatched order type', function () use ($transport, $HOOK) {
    throws(
        WebhookException::class,
        fn () => makeClient($transport, ['now' => fn () => 1787803300])->parsePayoutWebhook(
            $HOOK['input']['method'],
            $HOOK['input']['path'],
            $HOOK['headers'],
            $HOOK['body'],
            $HOOK['input']['rawQuery']
        )
    );
});

test('webhook rejects an eventId that differs from the header', function () use ($transport, $HOOK) {
    $headers = ['Webhook-Event-Id' => 'evt_0000000000000000000000000Z'] + $HOOK['headers'];
    throws(
        WebhookException::class,
        fn () => makeClient($transport, ['now' => fn () => 1787803300])->parsePaymentWebhook(
            $HOOK['input']['method'],
            $HOOK['input']['path'],
            $headers,
            $HOOK['body'],
            $HOOK['input']['rawQuery']
        )
    );
});

foreach ([
    'empty baseUrl' => ['baseUrl' => ''],
    'baseUrl uses http' => ['baseUrl' => 'http://api.example.com'],
    'baseUrl uses a non-https scheme' => ['baseUrl' => 'ftp://api.example.com'],
    'baseUrl has a path' => ['baseUrl' => 'https://api.example.com/api/v1'],
    'baseUrl is not a URL' => ['baseUrl' => 'not-a-url'],
    'empty accessKey' => ['accessKey' => ''],
    'invalid merchant private key' => ['merchantPrivateKeyBase64' => 'bm90LWEta2V5'],
    'empty platformBodyKeyId' => ['platformBodyKeyId' => ''],
    'platform body public key has the wrong length' => ['platformBodyPublicKeyBase64' => 'c2hvcnQ='],
    'empty webhook public key set' => ['platformWebhookPublicKeys' => []],
] as $name => $override) {
    test("config validation: {$name}", function () use ($transport, $override) {
        throws(ConfigException::class, fn () => makeClient($transport, $override));
    });
}

test('submitTradeNo: plain JSON, unsigned, unencrypted', function () use ($transport, &$captured, &$nextResponse) {
    $nextResponse = [
        'status' => 200,
        'body' => json_encode(['code' => 200, 'msg' => 'OK', 'data' => [
            'status' => 1,
            'orderStatus' => 'PENDING',
        ]]),
    ];

    $got = makeClient($transport)->submitPaymentTradeNo('P1', 'UTR123');

    eq($got['status'], 1);
    eq($got['orderStatus'], 'PENDING');
    eq($captured['method'], 'POST');
    eq($captured['url'], 'https://api.example.com/api/v1/payment/submitTradeNo');

    $h = array_change_key_case($captured['headers']);
    eq($h['content-type'], 'application/json');
    ok(!isset($h['signature']), 'public endpoints are not signed');
    ok(!isset($h['content-encryption']), 'body is not encrypted');
    eq($captured['body'], '{"orderNo":"P1","tradeNo":"UTR123"}');
});

test('submitTradeNo: a refusal still answers 200/200 and does not throw, status is 0', function () use ($transport, &$nextResponse) {
    $nextResponse = [
        'status' => 200,
        'body' => json_encode(['code' => 200, 'msg' => 'OK', 'data' => [
            'status' => 0,
            'message' => 'too many requests, please retry later',
        ]]),
    ];

    $got = makeClient($transport)->submitPaymentTradeNo('P1', 'UTR123');

    eq($got['status'], 0);
    ok(str_contains($got['message'], 'too many requests'), 'refusal carries a reason');
});

foreach ([['', 'UTR'], ['P1', ''], [' ', 'UTR'], ['P1', ' ']] as $case) {
    test("submitTradeNo: missing parameter is rejected ({$case[0]}|{$case[1]})", function () use ($transport, $case) {
        throws(RequestException::class, fn () => makeClient($transport)->submitPaymentTradeNo($case[0], $case[1]));
    });
}

test('addExtraInfo: optional fields are omitted rather than sent empty', function () use ($transport, &$captured, &$nextResponse) {
    $nextResponse = [
        'status' => 200,
        'body' => json_encode(['code' => 200, 'msg' => 'OK', 'data' => [
            'status' => 1,
            'paymentUrl' => 'https://h5.example/p/1',
        ]]),
    ];
    $client = makeClient($transport);

    $got = $client->addPaymentExtraInfo('P1', 'PK_JAZZCASH', ['mobile' => '03001234567']);
    eq($got['paymentUrl'], 'https://h5.example/p/1');
    eq($captured['url'], 'https://api.example.com/api/v1/payment/addExtraInfo');
    eq($captured['body'], '{"orderNo":"P1","payMethod":"PK_JAZZCASH","extra":{"mobile":"03001234567"}}');

    $client->addPaymentExtraInfo('P1');
    eq($captured['body'], '{"orderNo":"P1"}');

    throws(RequestException::class, fn () => $client->addPaymentExtraInfo(' '));
});

// Rules.php is generated; these cases guard how the tables are applied. Half of them
// are positive: a wrong rejection blocks merchants until the next SDK release.

function payReq(string $currency, array $paymentMethod): array
{
    return [
        'merchantOrderNo' => 'M1', 'currency' => $currency, 'amount' => '1.00',
        'paymentMethod' => $paymentMethod, 'webhookUrl' => 'https://m.example.com/w',
    ];
}

foreach ([
    ['BRL', [], 'code is required'],
    ['PKR', ['code' => 'PK_JAZZCASH',
             'pkJazzcash' => ['mobile' => '03001234567'],
             'pkEasypaisa' => ['mobile' => '03001234567']], 'only one method extra'],
    ['PKR', ['code' => 'PK_JAZZCASH', 'pkEasypaisa' => ['mobile' => '03001234567']],
        'does not match code'],
    ['PKR', ['code' => 'PH_GCASH', 'phGcash' => ['mobile' => '09171234567']],
        'not available for this currency'],
    ['IDR', ['code' => 'ID_VA',
             'idVa' => ['accountName' => 'Budi', 'email' => 'b@example.com', 'mobile' => '0812']],
        'extra.bankCode'],
] as [$ccy, $method, $fragment]) {
    test("validation: rejects {$ccy} {$fragment}", function () use ($transport, $ccy, $method, $fragment) {
        try {
            makeClient($transport)->createPayment(payReq($ccy, $method));
        } catch (RequestException $e) {
            ok(str_contains($e->getMessage(), $fragment), "message should contain '{$fragment}', got {$e->getMessage()}");
            return;
        }
        throw new \AssertionError('expected RequestException');
    });
}

foreach ([
    // PKR / PHP pay-in has no required extras at the gateway; omitting extra entirely is valid
    ['PKR', ['code' => 'PK_JAZZCASH']],
    ['PKR', ['code' => 'PK_JAZZCASH', 'pkJazzcash' => ['mobile' => '03001234567']]],
    ['PHP', ['code' => 'PH_GCASH']],
    ['IDR', ['code' => 'ID_VA', 'idVa' => ['accountName' => 'Budi', 'email' => 'b@example.com',
                                           'mobile' => '0812', 'bankCode' => 'BCA']]],
    ['XYZ', ['code' => 'WHATEVER']],   // currency absent from the table passes through
    ['BRL', ['code' => 'PIX']],        // no code allowlist for this currency, nothing to reject on
] as [$ccy, $method]) {
    test("validation: accepts {$ccy} {$method['code']}", function () use ($transport, &$nextResponse, $ccy, $method) {
        $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{}}'];
        makeClient($transport)->createPayment(payReq($ccy, $method));
    });
}

// Conditional requirements: codes within one currency differ; a flattened table would wrongly reject IN_UPI
test('validation: INR payout conditional requirements', function () use ($transport, &$nextResponse) {
    $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{}}'];
    $client = makeClient($transport);
    $payout = fn (array $m) => [
        'merchantOrderNo' => 'M1', 'currency' => 'INR', 'amount' => '1.00',
        'payoutMethod' => $m, 'webhookUrl' => 'https://m.example.com/w',
    ];

    $client->createPayout($payout(['code' => 'IN_UPI', 'inUpi' => [
        'account' => 'mary@upi', 'name' => 'Mary', 'email' => 'm@example.com', 'mobile' => '9871476369',
    ]]));

    throws(RequestException::class, fn () => $client->createPayout($payout([
        'code' => 'IN_IFSC',
        'inIfsc' => ['name' => 'Mary', 'email' => 'm@example.com', 'mobile' => '9871476369'],
    ])));

    $client->createPayout($payout(['code' => 'IN_IFSC', 'inIfsc' => [
        'account' => '123456789', 'ifsc' => 'HDFC0001234',
        'name' => 'Mary', 'email' => 'm@example.com', 'mobile' => '9871476369',
    ]]));
});

// Top-level required fields and formats come from the shared vectors under protocol/testdata/validation;
// a failure here means PHP disagrees with the protocol, not that the vector is wrong.

$VALIDATION_REASON_FRAGMENT = [
    'missing_required_field' => fn (array $c) => 'required field is empty: ' . $c['field'],
    'invalid_amount' => fn (array $c) => 'amount must be',
    'invalid_webhook_url' => fn (array $c) => 'webhookUrl must be',
];

$validationFiles = glob(TESTDATA . '/validation/*.json');
sort($validationFiles);
foreach ($validationFiles as $file) {
    $vector = load('validation/' . basename($file));
    foreach ($vector['cases'] as $c) {
        test('validation vector ' . basename($file) . ' / ' . $c['name'],
            function () use ($transport, &$nextResponse, $vector, $c, $VALIDATION_REASON_FRAGMENT) {
                $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{}}'];
                $body = array_merge($vector['base'], $c['override']);
                $call = fn () => $vector['direction'] === 'payment'
                    ? makeClient($transport)->createPayment($body)
                    : makeClient($transport)->createPayout($body);
                if ($c['expect'] === 'accept') {
                    $call();
                    return;
                }
                try {
                    $call();
                    throw new \AssertionError('should reject');
                } catch (RequestException $e) {
                    $fragment = $VALIDATION_REASON_FRAGMENT[$c['reason']]($c);
                    ok(str_contains($e->getMessage(), $fragment), "want '{$fragment}', got " . $e->getMessage());
                }
            });
    }
}

test('receipt: blank order number is rejected, surrounding whitespace is trimmed', function () use ($transport, &$captured, &$nextResponse) {
    foreach (['', '  ', "\t"] as $bad) {
        throws(RequestException::class, fn () => makeClient($transport)->getPayoutReceipt($bad));
    }
    $nextResponse = ['status' => 200, 'body' => '{"code":200,"msg":"OK","data":{}}'];
    makeClient($transport)->getPayoutReceipt('  P202608270001 ');
    eq($captured['url'], 'https://api.example.com/api/v1/payouts/P202608270001/receipt');
});

echo "\n";
if ($failed === []) {
    echo "  {$passed} passed\n";
    exit(0);
}
echo '  ' . count($failed) . " failed, {$passed} passed\n\n";
foreach ($failed as $f) {
    echo "  ✗ {$f}\n";
}
exit(1);
