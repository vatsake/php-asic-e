<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Tsa;

use Vatsake\AsicE\Api\Tsa\TimestampToken;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates that the TSA responder certificate chains to a trusted CA and is authorised for timestamping.
 */
class ResponderCertificateValidator implements Validator
{
    public function __construct(private TimestampToken $token, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $lotl = Lotl::getInstance();
        $leafCert = $this->token->getTsaResponderCertificate();

        $parsedLeaf = openssl_x509_parse($leafCert);
        if ($parsedLeaf === false) {
            return new ValidationResult(false, 'Unable to parse TSA responder certificate.');
        }

        $maxRecursion = 10;
        $cert = $leafCert;
        while (true) {
            if ($lotl->verify($cert)) {
                break;
            }
            try {
                $cert = Utils::getIssuerCert($cert);
            } catch (\Exception $e) {
                return new ValidationResult(false, 'TSA responder certificate did not chain to any trusted CA.');
            }
            $maxRecursion--;
            if ($maxRecursion === 0) {
                return new ValidationResult(false, 'TSA responder certificate did not chain to any trusted CA (max recursion reached).');
            }
        }

        $extensions = $parsedLeaf['extensions'] ?? [];

        if (!array_key_exists('extendedKeyUsage', $extensions) || !str_contains($extensions['extendedKeyUsage'], 'Time Stamping')) {
            return new ValidationResult(false, 'Responder certificate is missing the time stamping extended key usage.', $extensions);
        }

        if (!array_key_exists('keyUsage', $extensions) || !str_contains($extensions['keyUsage'], 'Digital Signature')) {
            return new ValidationResult(false, 'Responder certificate key usage must include digital signature.', $extensions);
        }

        return new ValidationResult(true);
    }
}
