<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container\Signature;

use Psr\Log\LoggerInterface;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Api\Ocsp\OcspResponse;
use Vatsake\AsicE\Api\Tsa\TimestampToken;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Validation\Ocsp\OcspValidator;
use Vatsake\AsicE\Validation\Signature\SignatureValidator;
use Vatsake\AsicE\Validation\Tsa\TsaValidator;
use Vatsake\AsicE\Validation\ValidationResult;

final class FinalizedSignature
{
    private array $validationErrors = [];
    private ?LoggerInterface $logger = null;

    /**
     * @param array<string, array{0: DigestAlg, 1: string}> $realFileDigests needed for validation
     */
    public function __construct(private SignatureXml $signatureXml, private array $realFileDigests)
    {
        $this->logger = AsiceConfig::getLogger();
        $this->logger?->debug('finalized_signature.construct');
    }

    public function toXml(): string
    {
        return $this->signatureXml->toXml();
    }

    /**
     * @return \Vatsake\AsicE\Validation\ValidationResult[]
     */
    private function validateOcsp(): array
    {
        $startedAt = microtime(true);
        $this->logger?->debug('finalized_signature.validate_ocsp.start');

        $ocspResponse = new OcspResponse(base64_decode($this->signatureXml->getOcspToken()));
        $basicResponse = $ocspResponse->getBasicResponse();

        $ocspValidator = new OcspValidator();
        $result = $ocspValidator->validate($basicResponse, $this->signatureXml);

        $this->logger?->debug('finalized_signature.validate_ocsp.completed', [
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return $result;
    }

    /**
     * @return \Vatsake\AsicE\Validation\ValidationResult[]
     */
    private function validateTsa(): array
    {
        $startedAt = microtime(true);
        $this->logger?->debug('finalized_signature.validate_tsa.start');

        $token = new TimestampToken(base64_decode($this->signatureXml->getTimestampToken()));

        $tsaValidator = new TsaValidator();
        $result = $tsaValidator->validate($token, $this->signatureXml);

        $this->logger?->debug('finalized_signature.validate_tsa.completed', [
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return $result;
    }

    /**
     * @return array<int, ValidationResult>
     */
    private function validateSignature(): array
    {
        $startedAt = microtime(true);
        $this->logger?->debug('finalized_signature.validate_signature.start');

        $validator = new SignatureValidator();
        $result = $validator->validate($this->signatureXml, $this->realFileDigests);

        $this->logger?->debug('finalized_signature.validate_signature.completed', [
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return $result;
    }

    /**
     * This populates validation errors and returns true if no errors found.
     */
    public function isValid(): bool
    {
        $startedAt = microtime(true);
        $this->logger?->info('finalized_signature.is_valid.start');

        $results = [...$this->validateTsa(), ...$this->validateOcsp(), ...$this->validateSignature()];

        $this->validationErrors = [];
        foreach ($results as $result) {
            if (!$result->isValid) {
                $this->validationErrors[] = $result;
            }
        }

        $isValid = sizeof($this->validationErrors) === 0;

        $this->logger?->info('finalized_signature.is_valid.completed', [
            'isValid' => $isValid,
            'invalidCount' => count($this->validationErrors),
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return $isValid;
    }

    /**
     * @return array<int, ValidationResult>
     */
    public function getValidationErrors(): array
    {
        return $this->validationErrors;
    }
}
