# Changelog — php

Versions follow SemVer. Tags are `vX.Y.Z` on this repository.

## v0.1.1 — 2026-09-14

- Fixed: none of the exception classes could be autoloaded. They all live in one
  file, which PSR-4 never finds because it resolves a class to a file of the same
  name, so any thrown exception became a fatal "class not found" instead. The
  package now ships a classmap entry for that file.

## v0.1.0 — 2026-09-14

Initial public release.

- Ed25519 request signing (RFC 9421 HTTP Message Signatures) and X25519
  sealed-box body encryption for POST requests.
- Platform webhook verification: `verifyWebhook`, `parsePaymentWebhook`, `parsePayoutWebhook`.
- Endpoints: `createPayment`, `createPayout`, `queryPaymentByOrderNo`, `queryPaymentByMerchantOrderNo`, `queryPayoutByOrderNo`, `queryPayoutByMerchantOrderNo`, `getBalance`, `getUsdRate`, `getPayoutReceipt`, `getPaymentCheckout`, `submitPaymentTradeNo`, `addPaymentExtraInfo`.
- Local validation before signing: top-level required fields, decimal-string
  amount within `DECIMAL(18,2)`, `https` webhook URL, method-code shape and
  per-currency required extras. Format checks (phone, e-mail, IFSC) stay with
  the gateway.
- Error taxonomy: `RequestException` (rejected before sending), `TransportException` (sent or possibly sent, no response), `ApiException` (gateway business error), `ResponseException` (non-envelope response).
- Amounts, balances, fees and rates are decimal strings; idempotency key
  support.
