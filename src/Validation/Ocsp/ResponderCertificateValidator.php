<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Ocsp;

use Vatsake\AsicE\Api\Ocsp\OcspBasicResponse;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates that the OCSP responder certificate chains to a trusted CA and is authorised for OCSP signing.
 */
class ResponderCertificateValidator implements Validator
{
    public function __construct(private OcspBasicResponse $response, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $lotl = Lotl::getInstance();
        $cert = $this->response->getOcspResponderCertificate();

        $parsedLeaf = openssl_x509_parse($cert);
        if ($parsedLeaf === false) {
            return new ValidationResult(false, 'Unable to parse OCSP responder certificate.');
        }

        $maxRecursion = 10;
        while (true) {
            if ($lotl->verify($cert)) {
                break;
            }
            try {
                $cert = Utils::getIssuerCert($cert);
            } catch (\Exception $e) {
                return new ValidationResult(false, 'OCSP responder certificate did not chain to any trusted CA.');
            }
            $maxRecursion--;

            if ($maxRecursion === 0) {
                return new ValidationResult(false, 'OCSP responder certificate did not chain to any trusted CA (max recursion reached).');
            }
        }

        if (!str_contains($parsedLeaf['extensions']['extendedKeyUsage'], 'OCSP Signing')) {
            return new ValidationResult(false, 'Responder certificate is missing the "OCSP Signing" extended key usage.', $parsedLeaf['extensions']['extendedKeyUsage']);
        }

        // Older certificates might not have that key usage
        //if (!str_contains($parsedLeaf['extensions']['keyUsage'], 'Digital Signature')) {
        //    return new ValidationResult(false, 'Responder certificate key usage must include digital signature.', $parsedLeaf['extensions']['keyUsage']);
        //}

        return new ValidationResult(true);
    }
}
