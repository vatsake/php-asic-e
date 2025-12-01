<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Signature;

use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates that SignedProperties references match the signer certificate and digest values.
 */
class SignedPropertiesValidator implements Validator
{
    public function __construct(private SignatureXml $xml) {}

    public function validate(): ValidationResult
    {
        $digestMethod = $this->xml->getSignedPropertiesDigestMethod();
        $digest = $this->xml->getSignedPropertiesDigest();

        $signerCertificate = $this->xml->getSignerCertificate();
        $parsedSignerCert = openssl_x509_parse(Utils::formatAsPemCertificate($signerCertificate));
        if ($parsedSignerCert === false) {
            return new ValidationResult(false, 'Unable to parse signer certificate.', [$signerCertificate]);
        }

        $signerCertDigest = $this->xml->getSignedPropSignerDigest();
        $signerCertDigestAlg = $this->xml->getSignedPropSignerDigestAlg();
        $signerSerialNumber = $this->xml->getSignerSerialNumber();

        $calculatedSignerCertHash = base64_encode(hash($signerCertDigestAlg->value, base64_decode($signerCertificate), true));

        if ($calculatedSignerCertHash !== $signerCertDigest) {
            return new ValidationResult(false, 'Signer certificate digest in SignedProperties does not match the embedded certificate.', [
                'digestInSignedProperties' => $signerCertDigest,
                'calculatedDigest' => $calculatedSignerCertHash,
                'digestAlgorithm' => $signerCertDigestAlg->value,
            ]);
        }

        if (Utils::serialToNumber($parsedSignerCert['serialNumber']) !== $signerSerialNumber) {
            return new ValidationResult(false, 'Signer certificate serial number in SignedProperties does not match the embedded certificate.', [
                'certificateSerialNumber' => $parsedSignerCert['serialNumber'],
                'serialInSignedProperties' => $signerSerialNumber,
            ]);
        }

        // Some signatures keep ignorable whitespace nodes, so try both canonical forms
        foreach ([true, false] as $stripWhitespace) {
            $signedProperties = $this->xml->getSignedPropertiesCanonicalized($stripWhitespace);
            $calculatedHash = base64_encode(hash($digestMethod->value, $signedProperties, true));

            if ($digest === $calculatedHash) {
                return new ValidationResult(true);
            }
        }

        return new ValidationResult(
            false,
            'SignedProperties digest does not match the canonicalized content hash.',
            [
                'digestInSignedProperties' => $digest,
                'calculatedDigest' => $calculatedHash,
                'digestAlgorithm' => $digestMethod->value,
            ]
        );
    }
}
