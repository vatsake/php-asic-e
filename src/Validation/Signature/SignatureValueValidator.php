<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Signature;

use phpseclib3\File\ASN1\Maps\EcdsaSigValue;
use phpseclib3\Math\BigInteger;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Crypto\SignAlg;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Verifies the XML signature value using the embedded signer certificate.
 */
class SignatureValueValidator implements Validator
{
    public function __construct(private SignatureXml $xml) {}

    public function validate(): ValidationResult
    {
        $signatureValue = $this->xml->getSignatureValue();
        $signMethod = $this->xml->getSignedInfoSignMethod();

        $signature = $this->getSignature($signatureValue, $signMethod);
        if ($signature === null) {
            return new ValidationResult(false, 'Unable to decode signature value for signature validation.');
        }

        $cert = openssl_x509_read(Utils::formatAsPemCertificate($this->xml->getSignerCertificate()));
        if ($cert === false) {
            return new ValidationResult(false, 'Unable to parse signer certificate for signature validation.');
        }

        $signerPublicKey = openssl_pkey_get_public($cert);
        if ($signerPublicKey === false) {
            return new ValidationResult(false, 'Unable to extract public key from signer certificate.');
        }

        $sslError = null;

        // Some signatures keep ignorable whitespace nodes, so try both canonical forms
        foreach ([true, false] as $stripWhitespace) {
            $signedInfo = $this->xml->getSignedInfoCanonicalized($stripWhitespace);
            $result = openssl_verify($signedInfo, $signature, $signerPublicKey, $signMethod->getDigestName());

            if ($result === 1) {
                return new ValidationResult(true);
            }

            if ($result < 1) {
                $sslError = openssl_error_string();
            }
        }

        return new ValidationResult(
            false,
            'Signature value validation failed.',
            $sslError ? (['SSL_ERROR' => $sslError]) : null
        );
    }

    private function getSignature(string $signatureValue, SignAlg $signMethod): ?string
    {
        $decoded = base64_decode($signatureValue, true);
        if ($decoded === false) {
            return null;
        }

        if (str_contains($signMethod->value, 'rsa')) {
            return $decoded;
        }

        // ECDSA signatures are encoded as raw concatenated r|s values; convert to DER.
        $length = strlen($decoded);
        if ($length === 0 || ($length % 2) !== 0) {
            return null;
        }

        $half = $length / 2;
        $r = new BigInteger(substr($decoded, 0, $half), 256);
        $s = new BigInteger(substr($decoded, $half), 256);

        return Asn1Helper::encode(['r' => $r, 's' => $s], EcdsaSigValue::MAP);
    }
}
