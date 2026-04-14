<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation;

use Vatsake\AsicE\AsiceConfig;

abstract class ValidatorGroup
{
    abstract protected function getValidators(): array;

    public function validate(...$context): array
    {
        $logger = AsiceConfig::getLogger();
        $groupName = static::class;

        $results = [];
        foreach ($this->getValidators() as $validatorClass) {
            $startedAt = microtime(true);

            $validator = new $validatorClass(...$context);
            $result = $validator->validate();

            $durationMs = (int) round((microtime(true) - $startedAt) * 1000);
            $shortName = substr($validatorClass, strrpos($validatorClass, '\\') + 1);

            if ($result->isValid) {
                $logger?->debug('validator.passed', [
                    'group' => $groupName,
                    'validator' => $shortName,
                    'durationMs' => $durationMs,
                ]);
            } else {
                $logger?->warning('validator.failed', [
                    'group' => $groupName,
                    'validator' => $shortName,
                    'reason' => $result->reason,
                    'durationMs' => $durationMs,
                ]);
            }

            $results[] = $result;
        }

        return $results;
    }
}
