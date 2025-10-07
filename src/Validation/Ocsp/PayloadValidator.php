<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Ocsp;

use phpseclib3\File\ASN1;
use Vatsake\AsicE\Api\Ocsp\OcspBasicResponse;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates that the OCSP CertID fields reference the signer and issuer certificates in the signature.
 */
class PayloadValidator implements Validator
{
    public function __construct(private OcspBasicResponse $response, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $signerCertificate = Utils::addPemHeaders($this->xml->getSignerCertificate());
        $certs = $this->xml->getEncapsulatedCertificates();

        try {
            $issuerCertificate = Utils::getIssuerCert($signerCertificate, $certs);
        } catch (\Throwable $e) {
            return new ValidationResult(false, 'Unable to resolve issuer certificate for OCSP validation.', [$e->getMessage()]);
        }

        $parsedSignerCert = openssl_x509_parse($signerCertificate);
        if ($parsedSignerCert === false) {
            return new ValidationResult(false, 'Unable to parse signer certificate for OCSP validation.');
        }

        $hashInOcsp = base64_encode($this->response->getIssuerPublicKeyHash());
        $keyDigestAlg = $this->response->getIssuerPublicKeyHashAlg();

        $issuerPublicKey = $this->getIssuerPublicKey($issuerCertificate);
        if ($issuerPublicKey === null) {
            return new ValidationResult(false, 'Unable to extract issuer public key for OCSP CertID verification.');
        }
        $calculatedHash = base64_encode(hash($keyDigestAlg->value, $issuerPublicKey, true));

        if ($calculatedHash !== $hashInOcsp) {
            return new ValidationResult(
                false,
                'Issuer public-key hash in OCSP response does not match the certificate embedded in the signature.',
                [
                    'expected' => $hashInOcsp,
                    'calculated' => $calculatedHash,
                    'algorithm' => $keyDigestAlg->value,
                ]
            );
        }

        $snInOcsp = $this->response->getSignerSerialNumber();
        $snInXml = Utils::serialToNumber($parsedSignerCert['serialNumber']);
        if ($snInOcsp !== $snInXml) {
            return new ValidationResult(
                false,
                'Signer certificate serial number differs from the OCSP CertID serial.',
                [
                    'expected' => $snInXml,
                    'ocsp' => $snInOcsp,
                ]
            );
        }

        return new ValidationResult(true);
    }

    private function getIssuerPublicKey(string $certificate): ?string
    {
        $pubKey = openssl_get_publickey($certificate);
        if ($pubKey === false) {
            return null;
        }

        $details = openssl_pkey_get_details($pubKey);
        if ($details === false || !isset($details['key'])) {
            return null;
        }

        $derPublicKey = base64_decode(Utils::stripPubHeaders($details['key']), true);
        if ($derPublicKey === false) {
            return null;
        }

        $nodes = ASN1::decodeBER($derPublicKey);
        if (empty($nodes) || !isset($nodes[0]['content'][1]['content'])) {
            return null;
        }

        $key = $nodes[0]['content'][1]['content'];

        // TAG is not hashed
        return substr($key, 1);
    }
}
