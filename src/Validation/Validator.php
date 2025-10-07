<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation;

use Vatsake\AsicE\Validation\ValidationResult;

interface Validator
{
    public function validate(): ValidationResult;
}
