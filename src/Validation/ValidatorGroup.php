<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation;

abstract class ValidatorGroup
{
    abstract protected function getValidators(): array;

    public function validate(...$context): array
    {
        $results = [];
        foreach ($this->getValidators() as $validatorClass) {
            $validator = new $validatorClass(...$context);
            $results[] = $validator->validate();
        }
        return $results;
    }
}
