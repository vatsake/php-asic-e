<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Ocsp;

use Vatsake\AsicE\Api\Ocsp\OcspBasicResponse;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates the OCSP basic-response signature using the responder certificate.
 */
class SignatureValidator implements Validator
{
    public function __construct(private OcspBasicResponse $response, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $responderCert = $this->response->getOcspResponderCertificate();
        $publicKey = openssl_pkey_get_public($responderCert);
        if ($publicKey === false) {
            return new ValidationResult(false, 'Unable to extract public key from OCSP responder certificate.');
        }

        $signedData = $this->response->getSignedData();
        $signature = $this->response->getSignature();
        $signatureAlg = $this->response->getSignatureAlgorithm();

        $result = openssl_verify($signedData, $signature, $publicKey, $signatureAlg);
        if ($result === 1) {
            return new ValidationResult(true);
        }

        $context = ['algorithm' => $signatureAlg];
        if ($result === -1) {
            $context['SSL_ERROR'] = openssl_error_string();
        }

        return new ValidationResult(false, 'OCSP signature verification failed.', $context);
    }
}
