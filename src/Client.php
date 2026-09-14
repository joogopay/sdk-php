<?php

declare(strict_types=1);

namespace Joogopay\Sdk;

/**
 * Merchant API client.
 *
 * Sends requests through the built-in cURL extension by default; a transport
 * callable can be injected through the config.
 */
final class Client
{
    private const DEFAULT_TIMEOUT = 30;
    private const DEFAULT_MAX_RESPONSE_BYTES = 8388608; // 8 MiB
    private const DEFAULT_USER_AGENT = 'merchant-sdk-php';
    private const DEFAULT_ACCEPT_LANGUAGE = 'en-US';

    private string $baseUrl;
    private string $accessKey;
    private string $merchantPrivateKey;
    private string $bodyKeyId;
    private string $bodyPublicKey;
    /** @var array<string,string> keyId => raw Ed25519 public key bytes */
    private array $webhookKeys;
    private int $timeout;
    private string $userAgent;
    private string $acceptLanguage;
    private int $maxResponseBytes;
    /** @var callable(string,string,array<string,string>,?string):array{0:int,1:string} */
    private $transport;
    /** @var callable():int */
    private $now;

    /** @param array<string,mixed> $config */
    public function __construct(array $config)
    {
        $baseUrl = trim((string) ($config['baseUrl'] ?? ''));
        if ($baseUrl === '') {
            throw new ConfigException('sdk: baseUrl is required');
        }
        $parts = parse_url($baseUrl);
        if ($parts === false
            || empty($parts['scheme'])
            || strcasecmp((string) $parts['scheme'], 'https') !== 0
            || empty($parts['host'])
            || isset($parts['query'])
            || isset($parts['fragment'])
        ) {
            throw new ConfigException('sdk: baseUrl must be an absolute origin URL');
        }
        $path = $parts['path'] ?? '';
        if ($path !== '' && $path !== '/') {
            throw new ConfigException('sdk: baseUrl must not contain a path');
        }

        $accessKey = trim((string) ($config['accessKey'] ?? ''));
        if ($accessKey === '') {
            throw new ConfigException('sdk: accessKey is required');
        }
        $bodyKeyId = trim((string) ($config['platformBodyKeyId'] ?? ''));
        if ($bodyKeyId === '') {
            throw new ConfigException('sdk: platformBodyKeyId is required');
        }
        $webhookKeys = $config['platformWebhookPublicKeys'] ?? [];
        if (!is_array($webhookKeys) || $webhookKeys === []) {
            throw new ConfigException('sdk: platformWebhookPublicKeys is required');
        }

        $this->baseUrl = rtrim($baseUrl, '/');
        $this->accessKey = $accessKey;
        $this->merchantPrivateKey = self::decodeKey(
            $config['merchantPrivateKeyBase64'] ?? '',
            [SODIUM_CRYPTO_SIGN_SEEDBYTES, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES],
            'merchant Ed25519 private key'
        );
        $this->bodyKeyId = $bodyKeyId;
        $this->bodyPublicKey = self::decodeKey(
            $config['platformBodyPublicKeyBase64'] ?? '',
            [Protocol::X25519_PUBLIC_KEY_SIZE],
            'platform X25519 public key'
        );
        $this->webhookKeys = [];
        foreach ($webhookKeys as $keyId => $value) {
            $id = trim((string) $keyId);
            if ($id === '') {
                throw new ConfigException('sdk: platform webhook key id must not be empty');
            }
            $this->webhookKeys[$id] = self::decodeKey(
                $value,
                [Protocol::ED25519_PUBLIC_KEY_SIZE],
                'platform webhook Ed25519 public key'
            );
        }

        $this->timeout = (int) ($config['timeout'] ?? self::DEFAULT_TIMEOUT);
        $this->userAgent = (string) ($config['userAgent'] ?? self::DEFAULT_USER_AGENT);
        $this->acceptLanguage = (string) ($config['acceptLanguage'] ?? self::DEFAULT_ACCEPT_LANGUAGE);
        $this->maxResponseBytes = (int) ($config['maxResponseBytes'] ?? self::DEFAULT_MAX_RESPONSE_BYTES);
        $this->transport = $config['transport'] ?? $this->curlTransport(...);
        $this->now = $config['now'] ?? static fn (): int => time();
    }

    /** @param array<int,int> $sizes */
    private static function decodeKey(mixed $value, array $sizes, string $what): string
    {
        $raw = base64_decode(trim((string) $value), true);
        if ($raw === false || !in_array(strlen($raw), $sizes, true)) {
            throw new ConfigException("sdk: invalid {$what}");
        }
        return $raw;
    }

    /** @param array<string,mixed> $req */
    public function createPayment(array $req, ?string $idempotencyKey = null): mixed
    {
        self::validateCreateCommon($req);
        $this->validateMethod(
            (string) ($req['currency'] ?? ''),
            $req['paymentMethod'] ?? [],
            Rules::PAYMENT_METHOD_RULES
        );
        return $this->write('/api/v1/payments', $req, $idempotencyKey);
    }

    /** @param array<string,mixed> $req */
    public function createPayout(array $req, ?string $idempotencyKey = null): mixed
    {
        self::validateCreateCommon($req);
        $this->validateMethod(
            (string) ($req['currency'] ?? ''),
            $req['payoutMethod'] ?? [],
            Rules::PAYOUT_METHOD_RULES
        );
        return $this->write('/api/v1/payouts', $req, $idempotencyKey);
    }

    public function queryPaymentByOrderNo(string $orderNo): mixed
    {
        return $this->read('/api/v1/payments', ['orderNo' => $orderNo]);
    }

    public function queryPaymentByMerchantOrderNo(string $merchantOrderNo): mixed
    {
        return $this->read('/api/v1/payments', ['merchantOrderNo' => $merchantOrderNo]);
    }

    public function queryPayoutByOrderNo(string $orderNo): mixed
    {
        return $this->read('/api/v1/payouts', ['orderNo' => $orderNo]);
    }

    public function queryPayoutByMerchantOrderNo(string $merchantOrderNo): mixed
    {
        return $this->read('/api/v1/payouts', ['merchantOrderNo' => $merchantOrderNo]);
    }

    public function getPayoutReceipt(string $orderNo): mixed
    {
        $orderNo = self::validatePathOrderNo($orderNo);
        return $this->read('/api/v1/payouts/' . rawurlencode($orderNo) . '/receipt', []);
    }

    public function getBalance(string $currency): mixed
    {
        return $this->read('/api/v1/balances', ['currency' => $currency]);
    }

    public function getUsdRate(string $currency, string $payMethod): mixed
    {
        return $this->read('/api/v1/usd-rates', ['currency' => $currency, 'payMethod' => $payMethod]);
    }

    /** Hosted checkout lookup; unsigned and unencrypted. */
    public function getPaymentCheckout(string $orderNo): mixed
    {
        $url = $this->baseUrl . '/api/v1/payment/checkout?' . http_build_query(['orderNo' => $orderNo]);
        return $this->send($url, 'GET', [], null);
    }

    /**
     * Reports the upstream transaction reference (UTR) the payer entered on the
     * hosted checkout so the platform can match the transfer to the order.
     * Unsigned and unencrypted, like getPaymentCheckout.
     *
     * A refusal still answers HTTP 200 with envelope code 200: the outcome is
     * data['status'] (1 accepted, 0 refused, reason in data['message']).
     */
    public function submitPaymentTradeNo(string $orderNo, string $tradeNo): mixed
    {
        $no = trim($orderNo);
        $trade = trim($tradeNo);
        if ($no === '' || $trade === '') {
            throw new RequestException('sdk: invalid query parameter');
        }
        return $this->publicPost('/api/v1/payment/submitTradeNo', ['orderNo' => $no, 'tradeNo' => $trade]);
    }

    /**
     * Completes the payer details of an order created without them; the platform
     * only places the order with the channel after this call. payMethod and extra
     * may be omitted when the order already carries them. Unsigned and unencrypted;
     * data['status'] means the same as in submitPaymentTradeNo.
     *
     * @param array<string,string> $extra
     */
    public function addPaymentExtraInfo(string $orderNo, string $payMethod = '', array $extra = []): mixed
    {
        $no = trim($orderNo);
        if ($no === '') {
            throw new RequestException('sdk: invalid query parameter');
        }
        $body = ['orderNo' => $no];
        $method = trim($payMethod);
        if ($method !== '') {
            $body['payMethod'] = $method;
        }
        if ($extra !== []) {
            $body['extra'] = $extra;
        }
        return $this->publicPost('/api/v1/payment/addExtraInfo', $body);
    }

    /** @param array<string,mixed> $body */
    private function publicPost(string $path, array $body): mixed
    {
        return $this->send(
            $this->baseUrl . $path,
            'POST',
            ['Content-Type' => 'application/json'],
            self::encodeBody($body)
        );
    }

    /**
     * Serialisation happens before signing, so a failure here is a request error, never a transport one.
     * @param array<string,mixed> $body
     */
    private static function encodeBody(array $body): string
    {
        $raw = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($raw === false) {
            throw new RequestException('sdk: marshal request body: ' . json_last_error_msg());
        }
        return $raw;
    }

    private static function isEmptyValue(mixed $value): bool
    {
        return $value === null || (is_string($value) && trim($value) === '');
    }

    /**
     * Amounts are positive decimal strings; the gateway rejects JSON numbers.
     * Rules::AMOUNT_PATTERN mirrors the gateway regex and the DECIMAL(18,2) bound;
     * it admits only digits and a dot, so "greater than zero" reduces to "contains a non-zero digit".
     */
    private static function validateAmount(string $field, mixed $value): void
    {
        if ($value === null || $value === '') {
            throw new RequestException("sdk: required field is empty: {$field}");
        }
        if (!is_string($value)) {
            throw new RequestException(
                "sdk: {$field} must be a decimal string such as \"100.00\", got " . get_debug_type($value)
            );
        }
        if (preg_match(Rules::AMOUNT_PATTERN, $value) !== 1) {
            throw new RequestException("sdk: {$field} must be a positive decimal string: '{$value}'");
        }
        if (preg_match('/[1-9]/', $value) !== 1) {
            throw new RequestException("sdk: {$field} must be greater than 0");
        }
    }

    /** Mirrors the gateway rule: required, absolute URL, https scheme. */
    private static function validateWebhookUrl(string $field, mixed $value): void
    {
        if (!is_string($value) || self::isEmptyValue($value)) {
            throw new RequestException("sdk: required field is empty: {$field}");
        }
        if (!str_starts_with(strtolower($value), Rules::WEBHOOK_URL_PREFIX)) {
            $scheme = rtrim(Rules::WEBHOOK_URL_PREFIX, ':/');
            throw new RequestException("sdk: {$field} must be an absolute {$scheme} URL");
        }
    }

    /**
     * The four top-level fields the gateway marks required; rejecting blanks here
     * saves a signed and encrypted round trip that would end in INVALID_FIELD.
     *
     * @param array<string,mixed> $body
     */
    private static function validateCreateCommon(array $body): void
    {
        foreach (Rules::CREATE_REQUIRED_TEXT_FIELDS as $field) {
            if (self::isEmptyValue($body[$field] ?? null)) {
                throw new RequestException("sdk: required field is empty: {$field}");
            }
        }
        self::validateAmount('amount', $body['amount'] ?? null);
        self::validateWebhookUrl('webhookUrl', $body['webhookUrl'] ?? null);
    }

    /** The caller rawurlencodes the returned value before it enters the path and the signature base. */
    private static function validatePathOrderNo(string $orderNo): string
    {
        $value = trim($orderNo);
        if ($value === '') {
            throw new RequestException('sdk: invalid path parameter');
        }
        return $value;
    }

    /**
     * Checks method shape and required extras against the generated Rules tables;
     * with validateCreateCommon this is all the local validation that
     * protocol/merchant-api.md (Client-side validation) specifies. Format checks
     * (phone length, e-mail, IFSC...) stay with the gateway on purpose: they evolve
     * per currency and channel, and a copy here would drift and block merchants
     * until the next SDK release.
     *
     * @param array<string,mixed> $method
     * @param array<string,array<string,mixed>> $rules
     */
    private function validateMethod(string $currency, array $method, array $rules): void
    {
        $code = trim((string) ($method['code'] ?? ''));
        if ($code === '') {
            throw new RequestException('sdk: method code is required');
        }

        $present = [];
        foreach ($method as $key => $value) {
            if ($key !== 'code' && $value !== null) {
                $present[] = (string) $key;
            }
        }
        sort($present);

        if (count($present) > 1) {
            throw new RequestException('sdk: only one method extra may be set: ' . implode(', ', $present));
        }
        $want = Rules::METHOD_EXTRA_FIELDS[$code] ?? null;
        if (count($present) === 1 && $want !== null && $present[0] !== $want) {
            throw new RequestException(
                "sdk: method extra does not match code: {$code} expects '{$want}', got '{$present[0]}'"
            );
        }

        $rule = $rules[strtoupper(trim($currency))] ?? null;
        // Unknown currencies pass through to the gateway: this table may lag behind it
        if ($rule === null) {
            return;
        }
        if ($rule['codes'] !== [] && !in_array($code, $rule['codes'], true)) {
            throw new RequestException(
                "sdk: method is not available for this currency: {$code} for {$currency}"
            );
        }

        $need = array_merge($rule['required'], $rule['byMethod'][$code] ?? []);
        if ($need === []) {
            return;
        }
        $extra = $present === [] ? [] : ($method[$present[0]] ?? []);
        if (!is_array($extra)) {
            throw new RequestException('sdk: method extra must be an object: ' . $present[0]);
        }
        foreach ($need as $field) {
            if (self::isEmptyValue($extra[$field] ?? null)) {
                throw new RequestException(
                    "sdk: required extra field is empty: extra.{$field} for {$currency} {$code}"
                );
            }
        }
    }

    /**
     * Verifies a platform webhook (request shape, Content-Digest, event id,
     * signature freshness, Ed25519 signature) and returns the decoded payload.
     *
     * @param array<string,string> $headers
     * @return array<string,mixed>
     */
    public function verifyWebhook(
        string $method,
        string $path,
        array $headers,
        string $body,
        string $rawQuery = ''
    ): array {
        if (strtoupper($method) !== 'POST') {
            throw new WebhookException('sdk: webhook must be POST');
        }
        $lowered = array_change_key_case($headers);
        if (trim($lowered['content-type'] ?? '') !== 'application/json') {
            throw new WebhookException('sdk: webhook Content-Type must be application/json');
        }
        if ($body === '' || strlen($body) > Protocol::MAX_WIRE_BODY_BYTES) {
            throw new WebhookException('sdk: invalid webhook body size');
        }
        $digestHeader = $lowered[strtolower(Protocol::HEADER_CONTENT_DIGEST)] ?? '';
        if (!Protocol::verifyContentDigest($body, $digestHeader)) {
            throw new WebhookException('sdk: webhook Content-Digest mismatch');
        }

        $eventId = trim($lowered[strtolower(Protocol::HEADER_WEBHOOK_EVENT_ID)] ?? '');
        Protocol::validateWebhookEventId($eventId);
        $payload = json_decode($body, true);
        if (!is_array($payload)) {
            throw new WebhookException('sdk: invalid webhook body');
        }
        if (($payload['eventId'] ?? null) !== $eventId) {
            throw new WebhookException('sdk: webhook event id mismatch');
        }

        $params = Protocol::parsePlatformSignatureInput(
            $lowered[strtolower(Protocol::HEADER_SIGNATURE_INPUT)] ?? ''
        );
        Protocol::validateSignatureParams($params, ($this->now)());
        $publicKey = $this->webhookKeys[$params['keyId']] ?? null;
        if ($publicKey === null) {
            throw new WebhookException('sdk: webhook platform key not found');
        }

        $signature = Protocol::parseSignature(
            $lowered[strtolower(Protocol::HEADER_SIGNATURE)] ?? '',
            Protocol::SIGNATURE_LABEL_PLATFORM
        );
        $base = Protocol::signatureBase($params, 'POST', $path, $rawQuery, $headers);
        Protocol::verifyEd25519($publicKey, $base, $signature);
        return $payload;
    }

    /** @param array<string,string> $headers @return array<string,mixed> */
    public function parsePaymentWebhook(
        string $method,
        string $path,
        array $headers,
        string $body,
        string $rawQuery = ''
    ): array {
        return self::requireWebhookFields(
            $this->verifyWebhook($method, $path, $headers, $body, $rawQuery),
            Status::WEBHOOK_ORDER_TYPE_PAYMENT
        );
    }

    /** @param array<string,string> $headers @return array<string,mixed> */
    public function parsePayoutWebhook(
        string $method,
        string $path,
        array $headers,
        string $body,
        string $rawQuery = ''
    ): array {
        return self::requireWebhookFields(
            $this->verifyWebhook($method, $path, $headers, $body, $rawQuery),
            Status::WEBHOOK_ORDER_TYPE_PAYOUT
        );
    }

    /** @param array<string,mixed> $payload @return array<string,mixed> */
    private static function requireWebhookFields(array $payload, string $orderType): array
    {
        if (($payload['eventId'] ?? '') === ''
            || ($payload['orderType'] ?? '') !== $orderType
            || ($payload['orderNo'] ?? '') === ''
            || ($payload['merchantOrderNo'] ?? '') === ''
            || ($payload['status'] ?? '') === ''
        ) {
            throw new WebhookException('sdk: invalid webhook body');
        }
        return $payload;
    }

    /** @param array<string,mixed> $body */
    private function write(string $path, array $body, ?string $idempotencyKey): mixed
    {
        $url = $this->baseUrl . $path;
        try {
            $key = trim($idempotencyKey ?? Protocol::newNonce());
            Protocol::validateIdempotencyKey($key);

            $wireBody = Protocol::sealBodyEnvelope(
                self::encodeBody($body),
                $this->bodyPublicKey,
                $this->bodyKeyId
            );
            $params = Protocol::newMerchantWriteSignatureParams(Protocol::newNonce(), ($this->now)());

            $headers = [
                'Content-Type' => 'application/json',
                Protocol::HEADER_CONTENT_ENCRYPTION => Protocol::CONTENT_ENCRYPTION,
                Protocol::HEADER_CONTENT_DIGEST => Protocol::contentDigestSha256($wireBody),
                Protocol::HEADER_IDEMPOTENCY_KEY => $key,
                Protocol::HEADER_MERCHANT_ACCESS_KEY => $this->accessKey,
            ];
            $headers[Protocol::HEADER_SIGNATURE_INPUT] = Protocol::signatureInputHeader($params);
            $base = Protocol::signatureBase($params, 'POST', parse_url($url, PHP_URL_PATH) ?: '/', '', $headers);
            $headers[Protocol::HEADER_SIGNATURE] = Protocol::signEd25519(
                $this->merchantPrivateKey,
                Protocol::SIGNATURE_LABEL_MERCHANT,
                $base
            );
        } catch (ProtocolException $e) {
            // Sealing and signing happen before the request is sent.
            throw new RequestException('sdk: build signed request: ' . $e->getMessage(), 0, $e);
        }
        return $this->send($url, 'POST', $headers, $wireBody);
    }

    /** @param array<string,string> $query */
    private function read(string $path, array $query): mixed
    {
        foreach ($query as $key => $value) {
            if (trim((string) $value) === '') {
                throw new RequestException("sdk: invalid query parameter: {$key}");
            }
        }
        $rawQuery = $query === [] ? '' : http_build_query($query);
        $url = $this->baseUrl . $path . ($rawQuery !== '' ? '?' . $rawQuery : '');

        try {
            Protocol::validateMerchantReadQuery($rawQuery);
            $params = Protocol::newMerchantReadSignatureParams(Protocol::newNonce(), ($this->now)());

            $headers = [Protocol::HEADER_MERCHANT_ACCESS_KEY => $this->accessKey];
            $headers[Protocol::HEADER_SIGNATURE_INPUT] = Protocol::signatureInputHeader($params);
            $base = Protocol::signatureBase(
                $params,
                'GET',
                parse_url($url, PHP_URL_PATH) ?: '/',
                $rawQuery,
                $headers
            );
            $headers[Protocol::HEADER_SIGNATURE] = Protocol::signEd25519(
                $this->merchantPrivateKey,
                Protocol::SIGNATURE_LABEL_MERCHANT,
                $base
            );
        } catch (ProtocolException $e) {
            // Signing happens before the request is sent.
            throw new RequestException('sdk: build signed request: ' . $e->getMessage(), 0, $e);
        }
        return $this->send($url, 'GET', $headers, null);
    }

    /** @param array<string,string> $headers */
    private function send(string $url, string $method, array $headers, ?string $body): mixed
    {
        $headers += [
            'Accept' => 'application/json',
            'Accept-Language' => $this->acceptLanguage,
            'User-Agent' => $this->userAgent,
        ];
        [$status, $raw] = ($this->transport)($url, $method, $headers, $body);
        return $this->decode($status, $raw);
    }

    /**
     * @param array<string,string> $headers
     * @return array{0:int,1:string}
     */
    private function curlTransport(string $url, string $method, array $headers, ?string $body): array
    {
        $curlHeaders = [];
        foreach ($headers as $name => $value) {
            $curlHeaders[] = "{$name}: {$value}";
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $curlHeaders,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $raw = curl_exec($ch);
        if ($raw === false) {
            // Connect failure or timeout: the request may have reached the platform.
            throw new TransportException('sdk: send request: ' . curl_error($ch));
        }
        return [(int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), (string) $raw];
    }

    private function decode(int $httpStatus, string $raw): mixed
    {
        if (strlen($raw) > $this->maxResponseBytes) {
            throw new ResponseTooLargeException('sdk: response body exceeds maxResponseBytes');
        }
        $envelope = json_decode($raw, true);
        if (!is_array($envelope) || array_is_list($envelope)) {
            throw new ResponseException($httpStatus, $raw);
        }
        // HTTP 200 with a non-200 envelope code is still a business failure
        if ($httpStatus !== 200 || ($envelope['code'] ?? null) !== 200) {
            $data = $envelope['data'] ?? null;
            throw new ApiException(
                $httpStatus,
                is_int($envelope['code'] ?? null) ? $envelope['code'] : 0,
                (string) ($envelope['msg'] ?? ''),
                is_array($data) ? (string) ($data['message'] ?? '') : '',
                (string) ($envelope['traceId'] ?? ''),
                $raw
            );
        }
        // A success envelope always carries the business object; handing back null
        // would let a caller record an order that has no orderNo as successful.
        if (!is_array($envelope['data'] ?? null)) {
            throw new ResponseException($httpStatus, $raw);
        }
        return $envelope['data'];
    }
}
