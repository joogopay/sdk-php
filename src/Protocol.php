<?php

declare(strict_types=1);

namespace Joogopay\Sdk;

/**
 * Merchant request signing and platform webhook verification.
 *
 * Implements protocol/signature.md, protocol/body-encryption.md and
 * protocol/webhook.md; the vectors under protocol/testdata pin the wire format
 * byte for byte across the language SDKs.
 *
 * Depends only on the built-in sodium and hash extensions.
 */
final class Protocol
{
    public const HEADER_MERCHANT_ACCESS_KEY = 'Merchant-Access-Key';
    public const HEADER_WEBHOOK_EVENT_ID = 'Webhook-Event-Id';
    public const HEADER_CONTENT_ENCRYPTION = 'Content-Encryption';
    public const HEADER_CONTENT_DIGEST = 'Content-Digest';
    public const HEADER_IDEMPOTENCY_KEY = 'Idempotency-Key';
    public const HEADER_SIGNATURE_INPUT = 'Signature-Input';
    public const HEADER_SIGNATURE = 'Signature';

    public const SIGNATURE_LABEL_MERCHANT = 'merchant';
    public const SIGNATURE_LABEL_PLATFORM = 'platform';
    public const SIGNATURE_ALG_ED25519 = 'ed25519';
    public const CONTENT_ENCRYPTION = 'sealedbox-v1-x25519-xsalsa20poly1305';

    public const MAX_PLAIN_BODY_BYTES = 1048576;      // 1 MiB
    public const MAX_WIRE_BODY_BYTES = 2097152;       // 2 MiB
    public const MAX_SIGNATURE_LIFETIME = 300;        // seconds
    public const X25519_PUBLIC_KEY_SIZE = 32;
    public const X25519_PRIVATE_KEY_SIZE = 32;
    public const ED25519_PUBLIC_KEY_SIZE = 32;
    public const ED25519_SIGNATURE_SIZE = 64;

    /** Fixed covered components; their order is the signature base order and part of the wire contract. */
    public const MERCHANT_WRITE_COVERED = [
        '@method', '@path', 'content-type', 'content-encryption',
        'content-digest', 'idempotency-key', 'merchant-access-key',
    ];
    public const MERCHANT_READ_COVERED = [
        '@method', '@path', '@query', 'merchant-access-key',
    ];
    public const PLATFORM_COVERED = [
        '@method', '@path', '@query', 'content-type', 'content-digest', 'webhook-event-id',
    ];

    public const ALLOWED_READ_QUERY_FIELDS = [
        'orderNo', 'merchantOrderNo', 'currency', 'payMethod', 'status',
        'startTime', 'endTime', 'page', 'pageSize', 'consentNo',
        'subscriptionPaymentNo', 'planNo', 'merchantPlanNo', 'merchantCustomerNo',
        'subscriptionNo', 'merchantSubscriptionNo', 'invoiceNo',
    ];

    private const CROCKFORD32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    private const COMPONENT_HEADERS = [
        'content-type' => 'Content-Type',
        'content-encryption' => self::HEADER_CONTENT_ENCRYPTION,
        'content-digest' => self::HEADER_CONTENT_DIGEST,
        'idempotency-key' => self::HEADER_IDEMPOTENCY_KEY,
        'merchant-access-key' => self::HEADER_MERCHANT_ACCESS_KEY,
        'webhook-event-id' => self::HEADER_WEBHOOK_EVENT_ID,
    ];

    /** @return array{label:string,covered:array<int,string>,created:int,expires:int,nonce:string,keyId:string,alg:string} */
    private static function makeParams(
        string $label,
        array $covered,
        string $nonce,
        ?int $now,
        string $keyId = ''
    ): array {
        $created = $now ?? time();
        return [
            'label' => $label,
            'covered' => $covered,
            'created' => $created,
            'expires' => $created + self::MAX_SIGNATURE_LIFETIME,
            'nonce' => $nonce,
            'keyId' => $keyId,
            'alg' => self::SIGNATURE_ALG_ED25519,
        ];
    }

    public static function newMerchantWriteSignatureParams(string $nonce, ?int $now = null): array
    {
        return self::makeParams(
            self::SIGNATURE_LABEL_MERCHANT, self::MERCHANT_WRITE_COVERED, $nonce, $now
        );
    }

    public static function newMerchantReadSignatureParams(string $nonce, ?int $now = null): array
    {
        return self::makeParams(
            self::SIGNATURE_LABEL_MERCHANT, self::MERCHANT_READ_COVERED, $nonce, $now
        );
    }

    public static function newPlatformSignatureParams(
        string $keyId,
        string $nonce,
        ?int $now = null
    ): array {
        return self::makeParams(
            self::SIGNATURE_LABEL_PLATFORM, self::PLATFORM_COVERED, $nonce, $now, $keyId
        );
    }

    /** Lowercase UUID v4. */
    public static function newNonce(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    /** Protocol values are ASCII without escapes, so JSON encoding yields exactly the quoted form the signature base uses. */
    private static function quote(string $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public static function signatureInputValue(array $params): string
    {
        $components = implode(' ', array_map(
            static fn (string $c): string => self::quote($c),
            $params['covered']
        ));
        $value = "({$components})"
            . ";created={$params['created']}"
            . ";expires={$params['expires']}"
            . ';nonce=' . self::quote($params['nonce']);
        if ($params['label'] === self::SIGNATURE_LABEL_PLATFORM) {
            $value .= ';keyid=' . self::quote($params['keyId']);
        }
        return $value . ';alg=' . self::quote($params['alg']);
    }

    public static function signatureInputHeader(array $params): string
    {
        self::validateSignatureParams($params, $params['created']);
        return $params['label'] . '=' . self::signatureInputValue($params);
    }

    private static function componentValue(
        string $component,
        string $method,
        string $path,
        string $rawQuery,
        array $headers
    ): string {
        if ($component === '@method') {
            return $method;
        }
        if ($component === '@path') {
            return $path !== '' ? $path : '/';
        }
        if ($component === '@query') {
            return '?' . $rawQuery;
        }
        $name = self::COMPONENT_HEADERS[$component] ?? null;
        if ($name === null) {
            throw new InvalidHeaderException("unknown covered component: {$component}");
        }
        $lowered = [];
        foreach ($headers as $key => $value) {
            $lowered[strtolower((string) $key)] = (string) $value;
        }
        $value = trim($lowered[strtolower($name)] ?? '');
        if (!self::validHeaderValue($value)) {
            throw new InvalidHeaderException("missing or invalid header: {$name}");
        }
        return $value;
    }

    /** RFC 9421 signature base. */
    public static function signatureBase(
        array $params,
        string $method,
        string $path,
        string $rawQuery = '',
        array $headers = []
    ): string {
        if (empty($params['covered'])) {
            throw new InvalidHeaderException('empty covered components');
        }
        $lines = [];
        foreach ($params['covered'] as $component) {
            $lines[] = self::quote($component) . ': '
                . self::componentValue($component, $method, $path, $rawQuery, $headers);
        }
        $lines[] = self::quote('@signature-params') . ': ' . self::signatureInputValue($params);
        return implode("\n", $lines);
    }

    private static function validHeaderValue(string $value): bool
    {
        return $value !== ''
            && trim($value) === $value
            && !str_contains($value, "\r")
            && !str_contains($value, "\n");
    }

    /** Accepts lowercase UUID v4 only. */
    public static function validUuidV4(string $value): bool
    {
        if (strlen($value) !== 36) {
            return false;
        }
        for ($i = 0; $i < 36; $i++) {
            $ch = $value[$i];
            if ($i === 8 || $i === 13 || $i === 18 || $i === 23) {
                if ($ch !== '-') {
                    return false;
                }
            } elseif ($i === 14) {
                if ($ch !== '4') {
                    return false;
                }
            } elseif ($i === 19) {
                if (!str_contains('89ab', $ch)) {
                    return false;
                }
            } elseif (!ctype_xdigit($ch) || strtolower($ch) !== $ch) {
                return false;
            }
        }
        return true;
    }

    public static function validateIdempotencyKey(string $value): void
    {
        if (!self::validUuidV4($value)) {
            throw new InvalidHeaderException('Idempotency-Key must be a lowercase UUID v4');
        }
    }

    public static function validateWebhookEventId(string $value): void
    {
        if (!str_starts_with($value, 'evt_') || strlen($value) !== 30) {
            throw new InvalidHeaderException('invalid Webhook-Event-Id');
        }
        foreach (str_split(substr($value, 4)) as $ch) {
            if (!str_contains(self::CROCKFORD32, $ch)) {
                throw new InvalidHeaderException('invalid Webhook-Event-Id');
            }
        }
    }

    /** Only ALLOWED_READ_QUERY_FIELDS may appear, each once and non-blank. */
    public static function validateMerchantReadQuery(string $rawQuery): void
    {
        if ($rawQuery === '') {
            return;
        }
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $rawQuery) === 1) {
            throw new InvalidHeaderException('query contains malformed percent-encoding');
        }
        $seen = [];
        foreach (explode('&', $rawQuery) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$rawKey, $rawValue] = array_pad(explode('=', $pair, 2), 2, '');
            $key = urldecode($rawKey);
            if (!in_array($key, self::ALLOWED_READ_QUERY_FIELDS, true)
                || isset($seen[$key])
                || trim(urldecode($rawValue)) === ''
            ) {
                throw new InvalidHeaderException("query field not allowed: {$key}");
            }
            $seen[$key] = true;
        }
    }

    public static function validateFreshness(array $params, int $now): void
    {
        if ($params['created'] <= 0
            || $params['expires'] <= 0
            || $params['expires'] <= $params['created']
            || $params['expires'] - $params['created'] > self::MAX_SIGNATURE_LIFETIME
        ) {
            throw new ExpiredSignatureException('invalid signature lifetime');
        }
        if ($now < $params['created'] - self::MAX_SIGNATURE_LIFETIME || $now > $params['expires']) {
            throw new ExpiredSignatureException('signature expired');
        }
    }

    private static function coveredComponentsAllowed(string $label, array $covered): bool
    {
        if ($label === self::SIGNATURE_LABEL_MERCHANT) {
            return $covered === self::MERCHANT_WRITE_COVERED
                || $covered === self::MERCHANT_READ_COVERED;
        }
        if ($label === self::SIGNATURE_LABEL_PLATFORM) {
            return $covered === self::PLATFORM_COVERED;
        }
        return false;
    }

    public static function validateSignatureParams(array $params, int $now): void
    {
        if (($params['label'] ?? '') === ''
            || ($params['alg'] ?? '') !== self::SIGNATURE_ALG_ED25519
            || !self::validUuidV4((string) ($params['nonce'] ?? ''))
        ) {
            throw new InvalidHeaderException('invalid signature params');
        }
        if ($params['label'] === self::SIGNATURE_LABEL_PLATFORM) {
            if (!self::validHeaderValue((string) ($params['keyId'] ?? ''))) {
                throw new InvalidHeaderException('platform signature requires keyid');
            }
        } elseif ($params['label'] !== self::SIGNATURE_LABEL_MERCHANT) {
            throw new InvalidHeaderException('unknown signature label');
        }
        if (!self::coveredComponentsAllowed($params['label'], $params['covered'])) {
            throw new InvalidHeaderException('covered components not allowed');
        }
        self::validateFreshness($params, $now);
    }

    public static function parseSignatureInput(string $value, string $label, array $covered): array
    {
        $prefix = $label . '=(';
        if (!str_starts_with($value, $prefix)) {
            throw new InvalidHeaderException('bad Signature-Input label');
        }
        $closing = strpos($value, ')');
        if ($closing === false
            || $closing + 1 >= strlen($value)
            || $value[$closing + 1] !== ';'
        ) {
            throw new InvalidHeaderException('bad Signature-Input components');
        }
        $rawComponents = preg_split(
            '/\s+/',
            substr($value, strlen($prefix), $closing - strlen($prefix)),
            -1,
            PREG_SPLIT_NO_EMPTY
        );
        if (count($rawComponents) !== count($covered)) {
            throw new InvalidHeaderException('covered components mismatch');
        }
        foreach ($rawComponents as $i => $raw) {
            if (json_decode($raw, true) !== $covered[$i]) {
                throw new InvalidHeaderException('covered components mismatch');
            }
        }

        $parts = explode(';', substr($value, $closing + 2));
        $expected = $label === self::SIGNATURE_LABEL_PLATFORM ? 5 : 4;
        if (count($parts) !== $expected) {
            throw new InvalidHeaderException('bad Signature-Input params');
        }
        $got = [];
        foreach ($parts as $part) {
            $idx = strpos($part, '=');
            if ($idx === false || $idx === 0) {
                throw new InvalidHeaderException('bad Signature-Input params');
            }
            $key = substr($part, 0, $idx);
            if (isset($got[$key])) {
                throw new InvalidHeaderException('bad Signature-Input params');
            }
            $got[$key] = substr($part, $idx + 1);
        }
        foreach (array_keys($got) as $key) {
            if (!in_array($key, ['created', 'expires', 'nonce', 'keyid', 'alg'], true)) {
                throw new InvalidHeaderException("unknown Signature-Input param: {$key}");
            }
        }
        if (isset($got['keyid']) && $label !== self::SIGNATURE_LABEL_PLATFORM) {
            throw new InvalidHeaderException('merchant signature must not carry keyid');
        }
        if (!isset($got['created'], $got['expires'], $got['nonce'], $got['alg'])
            || !ctype_digit($got['created'])
            || !ctype_digit($got['expires'])
        ) {
            throw new InvalidHeaderException('bad Signature-Input params');
        }
        return [
            'label' => $label,
            'covered' => $covered,
            'created' => (int) $got['created'],
            'expires' => (int) $got['expires'],
            'nonce' => (string) json_decode($got['nonce'], true),
            'alg' => (string) json_decode($got['alg'], true),
            'keyId' => isset($got['keyid']) ? (string) json_decode($got['keyid'], true) : '',
        ];
    }

    public static function parseMerchantWriteSignatureInput(string $value): array
    {
        return self::parseSignatureInput(
            $value, self::SIGNATURE_LABEL_MERCHANT, self::MERCHANT_WRITE_COVERED
        );
    }

    public static function parseMerchantReadSignatureInput(string $value): array
    {
        return self::parseSignatureInput(
            $value, self::SIGNATURE_LABEL_MERCHANT, self::MERCHANT_READ_COVERED
        );
    }

    public static function parsePlatformSignatureInput(string $value): array
    {
        return self::parseSignatureInput(
            $value, self::SIGNATURE_LABEL_PLATFORM, self::PLATFORM_COVERED
        );
    }

    /** RFC 9530 Content-Digest value (sha-256). */
    public static function contentDigestSha256(string $body): string
    {
        return 'sha-256=:' . base64_encode(hash('sha256', $body, true)) . ':';
    }

    public static function verifyContentDigest(string $body, string $header): bool
    {
        return hash_equals(self::contentDigestSha256($body), $header);
    }

    /** Accepts a 32-byte seed or the 64-byte seed||pub secret key libsodium uses. */
    private static function normalizePrivateKey(string $privateKey): string
    {
        $len = strlen($privateKey);
        if ($len === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            return $privateKey;
        }
        if ($len === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($privateKey));
        }
        throw new InvalidSignatureException('ed25519 private key must be 32 or 64 bytes');
    }

    public static function signEd25519(string $privateKey, string $label, string $base): string
    {
        if ($label === '' || $base === '') {
            throw new InvalidSignatureException('empty label or signature base');
        }
        $signature = sodium_crypto_sign_detached($base, self::normalizePrivateKey($privateKey));
        return self::signatureHeader($label, $signature);
    }

    public static function verifyEd25519(string $publicKey, string $base, string $signature): void
    {
        if (strlen($publicKey) !== self::ED25519_PUBLIC_KEY_SIZE
            || $base === ''
            || strlen($signature) !== self::ED25519_SIGNATURE_SIZE
        ) {
            throw new InvalidSignatureException('invalid ed25519 verify input');
        }
        if (!sodium_crypto_sign_verify_detached($signature, $base, $publicKey)) {
            throw new InvalidSignatureException('signature verification failed');
        }
    }

    public static function signatureHeader(string $label, string $signature): string
    {
        if (!self::validHeaderValue($label)
            || strlen($signature) !== self::ED25519_SIGNATURE_SIZE
        ) {
            throw new InvalidSignatureException('invalid signature header input');
        }
        return $label . '=:' . base64_encode($signature) . ':';
    }

    public static function parseSignature(string $value, string $label): string
    {
        if (!self::validHeaderValue($label)) {
            throw new InvalidSignatureException('invalid signature label');
        }
        $prefix = $label . '=:';
        if (!str_starts_with($value, $prefix) || !str_ends_with($value, ':')) {
            throw new InvalidSignatureException('malformed Signature header');
        }
        $raw = substr($value, strlen($prefix), -1);
        $signature = base64_decode($raw, true);
        if ($signature === false || strlen($signature) !== self::ED25519_SIGNATURE_SIZE) {
            throw new InvalidSignatureException('malformed Signature header');
        }
        return $signature;
    }

    /** Seals a plaintext POST body to the platform X25519 public key and returns the JSON wire body. */
    public static function sealBodyEnvelope(
        string $plaintext,
        string $publicKey,
        string $keyId
    ): string {
        if ($plaintext === '' || strlen($plaintext) > self::MAX_PLAIN_BODY_BYTES) {
            throw new InvalidEnvelopeException('invalid plaintext size');
        }
        if (strlen($publicKey) !== self::X25519_PUBLIC_KEY_SIZE
            || !self::validHeaderValue($keyId)
        ) {
            throw new InvalidEnvelopeException('invalid platform body key');
        }
        $ciphertext = sodium_crypto_box_seal($plaintext, $publicKey);
        // Same field order as the envelopes produced by the other SDKs
        return json_encode([
            'version' => 1,
            'alg' => self::CONTENT_ENCRYPTION,
            'keyId' => $keyId,
            'ciphertext' => base64_encode($ciphertext),
        ], JSON_UNESCAPED_SLASHES);
    }

    /** @return array{version:int,alg:string,keyId:string,ciphertext:string,ciphertextBytes:string} */
    public static function decodeBodyEnvelope(string $wireBody): array
    {
        if ($wireBody === '' || strlen($wireBody) > self::MAX_WIRE_BODY_BYTES) {
            throw new InvalidEnvelopeException('invalid envelope size');
        }
        $raw = json_decode($wireBody, true);
        if (!is_array($raw) || array_is_list($raw)) {
            throw new InvalidEnvelopeException('envelope is not a json object');
        }
        $keys = array_keys($raw);
        sort($keys);
        if ($keys !== ['alg', 'ciphertext', 'keyId', 'version']) {
            throw new InvalidEnvelopeException('unexpected envelope fields');
        }
        if ($raw['version'] !== 1
            || $raw['alg'] !== self::CONTENT_ENCRYPTION
            || !is_string($raw['keyId'])
            || !self::validHeaderValue($raw['keyId'])
            || !is_string($raw['ciphertext'])
            || $raw['ciphertext'] === ''
        ) {
            throw new InvalidEnvelopeException('invalid envelope');
        }
        $ciphertext = base64_decode($raw['ciphertext'], true);
        if ($ciphertext === false) {
            throw new InvalidEnvelopeException('invalid envelope ciphertext');
        }
        $raw['ciphertextBytes'] = $ciphertext;
        return $raw;
    }

    public static function peekBodyEnvelopeKeyId(string $wireBody): string
    {
        try {
            return self::decodeBodyEnvelope($wireBody)['keyId'];
        } catch (InvalidEnvelopeException) {
            return '';
        }
    }

    /**
     * Opens an envelope with the platform X25519 key pair (the server side of sealBodyEnvelope).
     *
     * @return array{0:string,1:string} [plaintext, keyId]
     */
    public static function openBodyEnvelope(
        string $wireBody,
        string $publicKey,
        string $privateKey
    ): array {
        if (strlen($publicKey) !== self::X25519_PUBLIC_KEY_SIZE
            || strlen($privateKey) !== self::X25519_PRIVATE_KEY_SIZE
        ) {
            throw new InvalidEnvelopeException('invalid platform body key pair');
        }
        $envelope = self::decodeBodyEnvelope($wireBody);
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $privateKey,
            $publicKey
        );
        $plaintext = sodium_crypto_box_seal_open($envelope['ciphertextBytes'], $keypair);
        if ($plaintext === false
            || $plaintext === ''
            || strlen($plaintext) > self::MAX_PLAIN_BODY_BYTES
        ) {
            throw new InvalidEnvelopeException('envelope decrypt failed');
        }
        return [$plaintext, $envelope['keyId']];
    }
}
