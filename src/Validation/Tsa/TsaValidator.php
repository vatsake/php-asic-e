<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Tsa;

use Vatsake\AsicE\Validation\ValidatorGroup;

final class TsaValidator extends ValidatorGroup
{
    protected function getValidators(): array
    {
        return [
            CmsSignatureValidator::class,
            MessageSignatureValidator::class,
            MessageTimeValidator::class,
            ResponderCertificateValidator::class
        ];
    }
}
