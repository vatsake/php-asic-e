<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Ocsp;

use DateTimeImmutable;
use Vatsake\AsicE\ASN1\OcspBasicResponse as Response;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Crypto\DigestAlg;

class OcspBasicResponse
{
    private array $data = [];

    public function __construct(string $derData)
    {
        $this->data = Asn1Helper::decode($derData, Response::MAP);
    }

    public function getIssuerPublicKeyHash(): string
    {
        return $this->data['tbsResponseData']['responses'][0]['certID']['issuerKeyHash'];
    }

    public function getIssuerPublicKeyHashAlg()
    {
        return DigestAlg::fromOid($this->data['tbsResponseData']['responses'][0]['certID']['hashAlgorithm']['algorithm']);
    }

    public function getSignerSerialNumber(): string
    {
        return (string) $this->data['tbsResponseData']['responses'][0]['certID']['serialNumber'];
    }

    /**
     *
     * @return 'good'|'revoked'|'unknown'
     */
    public function getCertificateStatus()
    {
        $certStatus = $this->data['tbsResponseData']['responses'][0]['certStatus'];
        return array_key_first($certStatus);
    }

    /**
     * Time when OCSP responder verified the certificate status
     */
    public function getStatusIssuedAt(): DateTimeImmutable
    {
        return DateTimeImmutable::createFromFormat(DateTimeImmutable::RFC2822, $this->data['tbsResponseData']['responses'][0]['thisUpdate']);
    }

    /**
     * Time when status expires (need to verify again)
     */
    public function getStatusValidUntil(): DateTimeImmutable|null
    {
        if (array_key_exists('nextUpdate', $this->data['tbsResponseData']['responses'][0])) {
            return DateTimeImmutable::createFromFormat(DateTimeImmutable::RFC2822, $this->data['tbsResponseData']['responses'][0]['nextUpdate']);
        }
        return null;
    }

    /**
     * Time when OCSP produced the response
     */
    public function getResponseProducedAt(): DateTimeImmutable|null
    {
        return DateTimeImmutable::createFromFormat(DateTimeImmutable::RFC2822, $this->data['tbsResponseData']['producedAt']);
    }

    /**
     *
     * @return string base64 encoded pem
     */
    public function getOcspResponderCertificate()
    {
        return Utils::addPemHeaders(base64_encode($this->data['certs'][0]->element));
    }

    public function getSignature(): string
    {
        // Ignore first byte;
        return substr($this->data['signature'], 1);
    }

    public function getSignatureAlgorithm()
    {
        $alg = strtolower($this->data['signatureAlgorithm']['algorithm']);

        if (preg_match('/sha(1|224|256|384|512)/', $alg, $matches)) {
            return 'sha' . $matches[1];
        }

        if (str_contains($alg, 'md5')) {
            return 'md5';
        }

        return null;
    }

    public function getSignedData(): string
    {
        return Asn1Helper::encode($this->data['tbsResponseData'], Response::MAP['children']['tbsResponseData']);
    }
}
