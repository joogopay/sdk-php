# Changelog — php

Versions follow SemVer. Tags are `vX.Y.Z` on this repository.

## v0.1.4 — 2026-09-21

- Method-code allowlists now cover every currency and direction the gateway
  validates, so a code the gateway would refuse is rejected before sending as
  "method not available" instead of coming back as an API error. Newly listed:
  pay-in `ARS` (`BANK_TRANSFER`, `CVU`, `QRIS`), `BRL` (`PIX`), `CLP` (`KHIPU`,
  `MACH`, `PAGO46`, `WEBPAY`), `COP` (`BREB`, `NEQUI`, `PSE`), `MXN` (`CASH`,
  `OXXO`, `SPEI`), `TRY` (`BANK_TRANSFER`); payout `ARS`, `CLP`, `MXN`
  (`BANK_TRANSFER`), `BRL` (`PIX`), `COP` (`BANK_CARD`, `BANK_TRANSFER`, `BREB`,
  `TRANSFIYA`), `IDR` (`ID_BANK_TRANSFER` and the five wallets), `TRY`
  (`BANK_TRANSFER`, `PAPARA`). Types and constants are unchanged.

## v0.1.3 — 2026-09-19

- Philippine GCash and Maya payouts take the wallet's own code (`PH_GCASH` /
  `PH_MAYA`) under its own extra field, matching Bangladesh, Indonesia and
  Pakistan; the channel derives `bankCode` from the code. Every other wallet,
  GrabPay included, still goes out under `PH_DF_WALLET` with `bankCode` naming
  the wallet, where it stays required as it is for `PH_DF_BANK`.

## v0.1.2 — 2026-09-18

- Needs a platform that accepts an omitted or `null` ARS `address` (platform
  release of 2026-09-18); against an earlier platform, send `address` as a string.
- ARS `BANK_TRANSFER` payout `address` is optional. Omitted, `null` and empty
  strings mean no address; non-empty strings are preserved. Other value types
  are rejected before sending. The other eight recipient fields remain required,
  and other currencies and methods retain their existing rules.
- USD payments accept `CASH_APP` only; USD payouts accept `CASH_APP`, `PAYPAL`
  and `CHIME`. Each carries its own extra field and required set, checked before
  the request goes out; earlier versions had no USD rules and passed every USD
  request through to the gateway.
- Documentation: the constructor docblock explains each config key;
  `IDEMPOTENCY_CONFLICT` and `CHANNEL_BUSY` handling in the error table; the `protocol/` links in the README are absolute so they resolve on the package page.

## v0.1.1 — 2026-09-14

- Fixed: none of the exception classes could be autoloaded. They all live in one
  file, which PSR-4 never finds because it resolves a class to a file of the same
  name, so any thrown exception became a fatal "class not found" instead. The
  package now ships a classmap entry for that file.
- Indonesia wallet payouts (`ID_DANA` / `ID_OVO` / `ID_GOPAY` / `ID_LINKAJA` /
  `ID_SHOPEEPAY`) validate under their own extra field (`idDana`, `idOvo`, ...),
  same shape as `idBankTransfer`. No API change.

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
