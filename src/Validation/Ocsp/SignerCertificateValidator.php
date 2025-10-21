<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Ocsp;

use Vatsake\AsicE\Api\Ocsp\OcspBasicResponse;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates the signer certificate OCSP status and ensures the response covers the signing time window.
 */
class SignerCertificateValidator implements Validator
{
    private const CLOCK_SKEW_SECONDS = 10 * 60;

    public function __construct(private OcspBasicResponse $response, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $certificateStatus = $this->response->getCertificateStatus();
        if ($certificateStatus !== 'good') {
            return new ValidationResult(false, sprintf(
                'Signer certificate OCSP status is "%s", expected "good".',
                $certificateStatus
            ));
        }

        $signingTimeTs = $this->xml->getSigningTime()->getTimestamp();
        $now = time();

        $thisUpdate = $this->response->getStatusIssuedAt();
        $nextUpdate = $this->response->getStatusValidUntil();
        $producedAt = $this->response->getResponseProducedAt();

        $thisUpdateTs = $thisUpdate->getTimestamp();
        $nextUpdateTs = $nextUpdate?->getTimestamp();
        $producedAtTs = $producedAt->getTimestamp();

        if (($thisUpdateTs - self::CLOCK_SKEW_SECONDS) > $signingTimeTs) {
            return new ValidationResult(false, sprintf(
                'OCSP status (thisUpdate: %s) is not valid at signing time (%s). Allowed clock skew: %d seconds.',
                date('c', $thisUpdateTs),
                date('c', $signingTimeTs),
                self::CLOCK_SKEW_SECONDS
            ), [
                'signingTime' => $signingTimeTs,
                'thisUpdate' => $thisUpdateTs,
                'skewSeconds' => self::CLOCK_SKEW_SECONDS,
            ]);
        }

        if ($nextUpdateTs && ($nextUpdateTs + self::CLOCK_SKEW_SECONDS) < $signingTimeTs) {
            return new ValidationResult(false, sprintf(
                'OCSP status expired (nextUpdate: %s) before signing time (%s). Allowed clock skew: %d seconds.',
                date('c', $nextUpdateTs),
                date('c', $signingTimeTs),
                self::CLOCK_SKEW_SECONDS
            ), [
                'signingTime' => $signingTimeTs,
                'thisUpdate' => $thisUpdateTs,
                'nextUpdate' => $nextUpdateTs,
                'skewSeconds' => self::CLOCK_SKEW_SECONDS,
            ]);
        }

        if ($producedAtTs > ($now + self::CLOCK_SKEW_SECONDS)) {
            return new ValidationResult(false, sprintf(
                'OCSP response producedAt (%s) is in the future (now: %s). Allowed clock skew: %d seconds.',
                date('c', $producedAtTs),
                date('c', $now),
                self::CLOCK_SKEW_SECONDS
            ), [
                'now' => $now,
                'producedAt' => $producedAtTs,
                'skewSeconds' => self::CLOCK_SKEW_SECONDS,
            ]);
        }

        if ($producedAtTs + self::CLOCK_SKEW_SECONDS < $thisUpdateTs) {
            return new ValidationResult(false, sprintf(
                'OCSP response producedAt (%s) predates thisUpdate (%s). Allowed clock skew: %d seconds.',
                date('c', $producedAtTs),
                date('c', $thisUpdateTs),
                self::CLOCK_SKEW_SECONDS
            ), [
                'producedAt' => $producedAtTs,
                'thisUpdate' => $thisUpdateTs,
                'skewSeconds' => self::CLOCK_SKEW_SECONDS,
            ]);
        }

        if ($thisUpdateTs > ($now + self::CLOCK_SKEW_SECONDS)) {
            return new ValidationResult(false, sprintf(
                'OCSP thisUpdate (%s) is in the future (now: %s). Allowed clock skew: %d seconds.',
                date('c', $thisUpdateTs),
                date('c', $now),
                self::CLOCK_SKEW_SECONDS
            ), [
                'now' => $now,
                'thisUpdate' => $thisUpdateTs,
                'skewSeconds' => self::CLOCK_SKEW_SECONDS,
            ]);
        }

        if ($nextUpdateTs !== null && ($now - self::CLOCK_SKEW_SECONDS) > $nextUpdateTs) {
            return new ValidationResult(false, sprintf(
                'OCSP status has expired (nextUpdate: %s is in the past, now: %s). Allowed clock skew: %d seconds.',
                date('c', $nextUpdateTs),
                date('c', $now),
                self::CLOCK_SKEW_SECONDS
            ), [
                'now' => $now,
                'nextUpdate' => $nextUpdateTs,
                'skewSeconds' => self::CLOCK_SKEW_SECONDS,
            ]);
        }

        return new ValidationResult(true);
    }
}
