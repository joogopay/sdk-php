<?php

declare(strict_types=1);

namespace Joogopay\Sdk;

/** Base class of every exception thrown by this SDK. */
class SdkException extends \RuntimeException {}

/** Base class of the protocol-level exceptions (headers, envelope, signature). */
class ProtocolException extends SdkException {}

/** Malformed signature headers, request shape or parameters. */
class InvalidHeaderException extends ProtocolException {}

/** Malformed body envelope or decryption failure. */
class InvalidEnvelopeException extends ProtocolException {}

/** Malformed signature or failed verification. */
class InvalidSignatureException extends ProtocolException {}

/** Invalid signature lifetime, or the signature is outside the accepted time window. */
class ExpiredSignatureException extends ProtocolException {}

/** Missing or invalid Client config. */
class ConfigException extends SdkException {}

/** The request was rejected before it was sent: local validation or a bad parameter. */
class RequestException extends SdkException {}

/**
 * No response was obtained after the request left the process (connection failure, timeout,
 * interrupted read). The outcome is unknown: query the order before retrying.
 */
class TransportException extends SdkException {}

/** Webhook verification or parsing failure. */
class WebhookException extends SdkException {}

/** Response body exceeds maxResponseBytes. */
class ResponseTooLargeException extends SdkException {}

/** The gateway returned a valid envelope with a non-success code. */
class ApiException extends SdkException
{
    /** The business code lives in the inherited $code (getCode()); a promoted readonly property cannot redeclare it. */
    public function __construct(
        public readonly int $httpStatus,
        int $code,
        public readonly string $msg = '',
        public readonly string $apiMessage = '',
        public readonly string $traceId = '',
        public readonly string $rawBody = '',
    ) {
        $detail = $apiMessage !== '' ? " message={$apiMessage}" : '';
        parent::__construct(
            "sdk: http={$httpStatus} code={$code} msg={$msg} traceId={$traceId}{$detail}",
            $code
        );
    }
}

/** The response is not a valid envelope JSON (an HTML error page or plain-text 502 from the gateway or a CDN). */
class ResponseException extends SdkException
{
    public function __construct(
        public readonly int $httpStatus,
        public readonly string $rawBody = '',
    ) {
        parent::__construct("sdk: http={$httpStatus} response is not a valid envelope JSON");
    }
}
