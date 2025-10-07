<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Signature;

use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates the embedded signer certificate against signing-time constraints and trusted anchors.
 */
class SignerCertificateValidator implements Validator
{
    public function __construct(private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $lotl = Lotl::getInstance();
        $signerCertificate = Utils::addPemHeaders($this->xml->getSignerCertificate());
        $signingTime = $this->xml->getSigningTime();
        $parsedCert = openssl_x509_parse($signerCertificate);

        if ($parsedCert === false) {
            return new ValidationResult(false, 'Unable to parse signer certificate.', [$signerCertificate]);
        }

        $signingTimestamp = $signingTime->getTimestamp();
        $validFrom = $parsedCert['validFrom_time_t'];
        $validTo = $parsedCert['validTo_time_t'];
        if ($signingTimestamp < $validFrom || $signingTimestamp > $validTo) {
            return new ValidationResult(false, 'Signer certificate was not valid at the signing time.', [
                'signingTime' => $signingTimestamp,
                'validFrom' => $validFrom,
                'validTo' => $validTo,
            ]);
        }

        $keyUsage = $parsedCert['extensions']['keyUsage'] ?? null;
        if ($keyUsage === null || (!str_contains($keyUsage, 'Non Repudiation') && !str_contains($keyUsage, 'Content Commitment'))) {
            return new ValidationResult(false, 'Signer certificate keyUsage must include Non Repudiation/Content Commitment.', [
                'keyUsage' => $keyUsage,
            ]);
        }

        $maxRecursion = 10;
        $cert = $signerCertificate;
        while (true) {
            if ($lotl->verify($cert)) {
                break;
            }
            try {
                $cert = Utils::getIssuerCert($cert);
            } catch (\Exception $e) {
                return new ValidationResult(false, 'Signer certificate did not chain to any trusted CA.');
            }
            $maxRecursion--;
            if ($maxRecursion === 0) {
                return new ValidationResult(false, 'Signer certificate did not chain to any trusted CA (max recursion reached).');
            }
        }

        return new ValidationResult(true);
    }
}
