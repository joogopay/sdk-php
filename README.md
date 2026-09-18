# JooGoPay SDK for PHP

PHP SDK for the merchant open API. Signing, digesting and body encryption are
handled by the SDK; merchants never assemble `Signature-Input`, `Content-Digest`
or the sealed-box envelope themselves.

## Protocol

[`protocol/`](https://github.com/joogopay/sdk-php/tree/main/protocol/) is the cross-language source of truth; the Go,
JavaScript, PHP, Python and Java SDKs share one set of test vectors:

| Item | Approach |
| --- | --- |
| Signature | Ed25519 with a fixed RFC 9421 profile |
| Digest | RFC 9530 `Content-Digest` (sha-256) |
| POST body | X25519 sealed-box envelope; the digest is computed over the ciphertext |
| GET | No encryption and no body; only the public query and the access key are signed |
| Webhook | Signed by the platform's Ed25519 key; the body is not encrypted |
| Merchant identity | Located by `Merchant-Access-Key` only; signature params carry **no keyId** |

## Installation

```
composer require joogopay/sdk
```

No third-party packages; only the `sodium`, `json` and `curl` extensions that
ship with PHP. PHP 8.2 or newer.

## Configuration

Merchants keep six values; only the private key is generated on the merchant
side, and the platform never receives it:

| Field | Description |
| --- | --- |
| `baseUrl` | HTTPS platform origin, without `/api/v1` |
| `accessKey` | Merchant access identifier issued by the platform |
| `merchantPrivateKeyBase64` | Merchant Ed25519 private key, base64, **stored on the merchant side only** |
| `platformBodyKeyId` | Current platform body key id (per deployment) |
| `platformBodyPublicKeyBase64` | Platform X25519 public key, base64, used to encrypt POST bodies |
| `platformWebhookPublicKeys` | Platform webhook Ed25519 public keys, indexed by keyId |

The Client rejects non-HTTPS base URLs. Synchronous responses remain plaintext
JSON; HTTPS/TLS is their confidentiality and integrity boundary.

## Quick start

```php
use Joogopay\Sdk\ApiException;
use Joogopay\Sdk\Client;
use Joogopay\Sdk\RequestException;
use Joogopay\Sdk\ResponseException;
use Joogopay\Sdk\TransportException;

$client = new Client([
    'baseUrl' => 'https://panama.joogopay.com',          // production origin; no /api/v1
    'accessKey' => 'mak_live_xxx',
    'merchantPrivateKeyBase64' => $merchantPrivateKey,        // merchant Ed25519 private key, base64
    'platformBodyKeyId' => 'body_20260827_01',
    'platformBodyPublicKeyBase64' => $platformBodyPublicKey,  // platform X25519 public key, base64
    'platformWebhookPublicKeys' => [                          // keyId -> platform Ed25519 public key, base64
        'pwhk_20260827_01' => $platformWebhookPublicKey,
    ],
]);

$order = $client->createPayment([
    'merchantOrderNo' => 'M20260101001',
    'currency' => 'BRL',
    'amount' => '100.00',                              // decimal string, never a float
    'paymentMethod' => ['code' => 'PIX', 'pix' => ['payerName' => 'Joao Silva']],
    'webhookUrl' => 'https://merchant.example/webhook/payments',
]);
echo $order['orderNo'], ' ', $order['status'], ' ', $order['action']['url'] ?? '';
```

### Two kinds of failure, opposite handling

| Error | Meaning | Handling |
| --- | --- | --- |
| `RequestException` | Rejected **before it was sent** (local validation, a bad parameter, or a request the SDK could not encode or sign) | Safe to mark failed; fix the request and retry under the same `merchantOrderNo` |
| `TransportException` | Handed to the transport, no usable response (connection failure, timeout, interrupted read) | Outcome unknown; **never mark a payout failed**. Query by `merchantOrderNo`, or resend the identical request under the same number |
| `ApiException` | The gateway returned a business error (`$e->msg` / `$e->apiMessage` / `$e->traceId`) | Branch on `msg`. `IDEMPOTENCY_CONFLICT`: the number is taken but the platform could not return its order, query that number and keep querying rather than switching numbers. `CHANNEL_ERROR`: the order may already exist, query by `merchantOrderNo` first and reuse that number only once the query returns `ORDER_NOT_FOUND`. `CHANNEL_BUSY`: refused before the order was created, so resend the same number after a back-off; this is the only channel error that needs no query first |
| `ResponseException` | The gateway or CDN returned something that is not an envelope (HTML 502, ...) | Outcome unknown; query before deciding |
| `ResponseTooLargeException` | A response arrived but exceeded the size limit and was discarded | Outcome unknown; the order was most likely created, query before deciding |
| Anything else | An unexpected error; assume the request may have arrived | Outcome unknown; query before deciding |

**`merchantOrderNo` is the only key that prevents a duplicate order.** A second
create with the same number never creates a second order: the platform answers
with the original order, or with `IDEMPOTENCY_CONFLICT` when it recognises the
number as taken but cannot return that order. The idempotency key travels with the request for tracing and
is **not** a deduplication key.

Two rules follow:

- After an unknown outcome, never allocate a new `merchantOrderNo`. Query the
  existing one, or resend the same request under the same number.
- A resend must carry identical parameters. The platform returns the original
  order without comparing fields, so a changed amount or account silently has no
  effect. To change anything, use a new `merchantOrderNo` and reconcile the
  original order first.

The SDK validates locally before signing (top-level required fields and formats,
method shape and required extras); the rules are defined in
[`protocol/merchant-api.md`](https://github.com/joogopay/sdk-php/blob/main/protocol/merchant-api.md#client-side-validation).
Format checks (phone length, e-mail, ...) stay with the gateway on purpose, so
the SDK never drifts from it.

### Next steps

Queries, idempotent retries and the full webhook flow are covered by the platform
documentation at <https://docs.joogopay.com>; its examples map one to one onto this
SDK. The wire protocol is in
[`protocol/webhook.md`](https://github.com/joogopay/sdk-php/blob/main/protocol/webhook.md) and
[`protocol/merchant-api.md`](https://github.com/joogopay/sdk-php/blob/main/protocol/merchant-api.md). Key points:

- After a create times out, query by `merchantOrderNo` before sending anything
  new; a deliberate retry repeats the same call with the same `merchantOrderNo`.
- For webhooks, pass the method, path, headers and the **raw, unparsed body
  bytes** to `$client->parsePaymentWebhook($method, $path, $headers, $rawBody)`;
  the SDK checks the digest, event id, time window and Ed25519 signature. Return
  2xx once handled and deduplicate by `eventId`.

## Amounts

Amounts, fees and rates in requests, responses, webhooks, balances, rates and
receipts are **always decimal strings** such as `"100.00"`. Never use floats.

## Order status

Only six external statuses exist: `PENDING` `PROCESSING` `SUCCEEDED` `FAILED`
`EXPIRED` `CANCELED`.

## Troubleshooting

| Situation | Action |
| --- | --- |
| Create request timed out | Query by `merchantOrderNo`; do not send a new order |
| Deliberate retry | Call the same method again with the same `merchantOrderNo` and identical parameters; the SDK regenerates the nonce on every request |
| Signature rejected | Check the server clock, `accessKey`, the merchant private key and the public key stored on the platform |
| Body decryption failed | Check that `platformBodyKeyId` and the public key belong to the current environment |
| Webhook verification failed | Check that the webhook key set contains the `keyid` from the header |

## Tests

```
php tests/run.php
```

The tests assert directly against the vectors in
[`protocol/testdata`](https://github.com/joogopay/sdk-php/tree/main/protocol/testdata/): `Signature-Input`, the signature
base and the signature value are compared byte for byte, and body encryption is
verified by decrypting ciphertext produced by the reference implementation.
