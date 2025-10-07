<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Tsa;

use Vatsake\AsicE\Api\Tsa\TimestampToken;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates the timestamp token signature using the TSA responder certificate.
 */
class CmsSignatureValidator implements Validator
{
    public function __construct(private TimestampToken $token, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $publicKey = openssl_pkey_get_public($this->token->getTsaResponderCertificate());

        if ($publicKey === false) {
            return new ValidationResult(false, 'Unable to extract public key from timestamp responder certificate.');
        }

        $signedData = $this->token->getSignedData();
        $signature = $this->token->getSignature();

        try {
            $signatureAlg = $this->token->getSignatureAlgorithm();
        } catch (\InvalidArgumentException $e) {
            return new ValidationResult(true, 'Unknown encryption, assuming correct', [$e->getMessage()]);
        }

        $valid = openssl_verify($signedData, $signature, $publicKey, $signatureAlg->getDigestName());
        return new ValidationResult((bool) $valid, $valid ? null : 'TSA signature verification failed.');
    }
}
