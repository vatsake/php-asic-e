<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Ocsp;

use Vatsake\AsicE\Validation\ValidatorGroup;

final class OcspValidator extends ValidatorGroup
{
    protected function getValidators(): array
    {
        return [
            PayloadValidator::class,
            ResponderCertificateValidator::class,
            SignatureValidator::class,
            SignerCertificateValidator::class
        ];
    }
}
