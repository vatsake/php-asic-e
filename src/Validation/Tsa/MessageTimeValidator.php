<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Tsa;

use Vatsake\AsicE\Api\Tsa\TimestampToken;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates timestamp generation time against the TSA certificate validity and the signature's signing time.
 */
class MessageTimeValidator implements Validator
{
    private const CLOCK_SKEW_SECONDS = 10 * 60;

    public function __construct(private TimestampToken $token, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $tsaCert = openssl_x509_parse($this->token->getTsaResponderCertificate());
        if ($tsaCert === false) {
            return new ValidationResult(false, 'Unable to parse TSA responder certificate.');
        }

        $tstInfo = $this->token->getTimestampInfo();
        $genTime = $tstInfo->getGenerationTime()->getTimestamp();
        $signingTime = $this->xml->getSigningTime()->getTimestamp();

        $validFrom = $tsaCert['validFrom_time_t'];
        $validUntil = $tsaCert['validTo_time_t'];

        if (($validFrom - self::CLOCK_SKEW_SECONDS) > $signingTime || ($validUntil + self::CLOCK_SKEW_SECONDS) < $signingTime) {
            return new ValidationResult(
                false,
                'Signature signing time falls outside the TSA certificate validity window.',
                [
                    'signingTime' => $signingTime,
                    'validFrom' => $validFrom,
                    'validUntil' => $validUntil,
                    'skewSeconds' => self::CLOCK_SKEW_SECONDS,
                ]
            );
        }

        if ($genTime < ($signingTime - self::CLOCK_SKEW_SECONDS)) {
            return new ValidationResult(
                false,
                'Timestamp generation time predates the claimed signing time.',
                [
                    'generatedAt' => $genTime,
                    'signingTime' => $signingTime,
                    'skewSeconds' => self::CLOCK_SKEW_SECONDS,
                ]
            );
        }

        if ($genTime < $validFrom || $genTime > $validUntil) {
            return new ValidationResult(
                false,
                'Timestamp generation time falls outside the TSA certificate validity period.',
                [
                    'generatedAt' => $genTime,
                    'validFrom' => $validFrom,
                    'validUntil' => $validUntil,
                ]
            );
        }

        return new ValidationResult(true);
    }
}
