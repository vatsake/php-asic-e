<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container\Signature;

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

    /**
     * @param SignatureXml $xml
     * @param array<string, array{0: DigestAlg, 1: string}> $fileDigests needed for validation
     */
    public function __construct(private SignatureXml $signatureXml, private array $realFileDigests)
    {
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
        $ocspResponse = new OcspResponse(base64_decode($this->signatureXml->getOcspToken()));
        $basicResponse = $ocspResponse->getBasicResponse();

        $ocspValidator = new OcspValidator();
        $result = $ocspValidator->validate($basicResponse, $this->signatureXml);
        return $result;
    }

    /**
     * @return \Vatsake\AsicE\Validation\ValidationResult[]
     */
    private function validateTsa(): array
    {
        $token = new TimestampToken(base64_decode($this->signatureXml->getTimestampToken()));

        $tsaValidator = new TsaValidator();
        $result = $tsaValidator->validate($token, $this->signatureXml);
        return $result;
    }

    private function validateSignature()
    {
        $validator = new SignatureValidator();
        $result = $validator->validate($this->signatureXml, $this->realFileDigests);
        return $result;
    }

    /**
     * This populates validation errors and returns true if no errors found.
     */
    public function isValid(): bool
    {
        $results = [...$this->validateTsa(), ...$this->validateOcsp(), ...$this->validateSignature()];

        $this->validationErrors = [];
        foreach ($results as $result) {
            if (!$result->isValid) {
                $this->validationErrors[] = $result;
            }
        }

        return sizeof($this->validationErrors) === 0;
    }

    /**
     * @return array<int, ValidationResult>
     */
    public function getValidationErrors(): array
    {
        return $this->validationErrors;
    }
}
