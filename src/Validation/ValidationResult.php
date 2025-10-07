<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation;

final class ValidationResult
{
    public function __construct(
        public readonly bool $isValid,
        public readonly ?string $reason = null,
        public readonly ?array $details = null,
    ) {
    }
}
