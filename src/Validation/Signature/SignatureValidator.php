<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Signature;

use Vatsake\AsicE\Validation\ValidatorGroup;

final class SignatureValidator extends ValidatorGroup
{
    protected function getValidators(): array
    {
        return [
            SignerCertificateValidator::class,
            SignedPropertiesValidator::class,
            SignatureValueValidator::class,
            FileDigestsValidator::class,
        ];
    }
}
