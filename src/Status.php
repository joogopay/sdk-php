<?php

declare(strict_types=1);

namespace Joogopay\Sdk;

/**
 * Public order statuses and webhook constants.
 *
 * Amounts, fees and rates are decimal strings throughout the API, never floats.
 */
final class Status
{
    public const PENDING = 'PENDING';
    public const PROCESSING = 'PROCESSING';
    public const SUCCEEDED = 'SUCCEEDED';
    public const FAILED = 'FAILED';
    public const EXPIRED = 'EXPIRED';
    public const CANCELED = 'CANCELED';
    public const REFUNDED = 'REFUNDED';

    /** Public order statuses. REFUNDED is payout-only; checkout progress is unchanged. */
    public const ALL = [
        self::PENDING, self::PROCESSING, self::SUCCEEDED,
        self::FAILED, self::EXPIRED, self::CANCELED, self::REFUNDED,
    ];

    public const WEBHOOK_ORDER_TYPE_PAYMENT = 'PAYMENT';
    public const WEBHOOK_ORDER_TYPE_PAYOUT = 'PAYOUT';

    /** Public money fields; each one is a decimal string, never a float. */
    public const MONEY_FIELDS = [
        'amount', 'paidAmount', 'refundAmount', 'minAmount', 'maxAmount', 'usdRate',
        'balance', 'lockBalance', 'paymentBalance', 'paymentLockBalance',
        'payoutBalance', 'payoutLockBalance',
    ];
}
