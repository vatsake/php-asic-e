<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Ocsp;

use Vatsake\AsicE\ASN1\OcspResponse as ASN1OcspResponse;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Exceptions\OcspException;

class OcspResponse
{
    private const BASIC_RESPONSE_OID = '1.3.6.1.5.5.7.48.1.1';

    private string $derData;

    private array $ocspResponse;

    public function __construct(string $derData)
    {
        $ocspResponse = Asn1Helper::decode($derData, ASN1OcspResponse::MAP);

        $status = $ocspResponse['responseStatus'];
        if ($status !== 'successful') {
            throw new OcspException("OCSP response is \"{$status}\"");
        }

        $this->derData = $derData;
        $this->ocspResponse = $ocspResponse;
    }

    /**
     *
     * @return string base64 encoded (used in XAdES document)
     */
    public function getToken(): string
    {
        return base64_encode($this->derData);
    }

    /**
     * Basic response inside the token
     *
     * Used for validation after signing
     */
    public function getBasicResponse(): OcspBasicResponse
    {
        $responseType = $this->ocspResponse['responseBytes']['responseType'];
        if ($responseType !== self::BASIC_RESPONSE_OID) {
            throw new OcspException("Response type {$responseType} not supported");
        }
        return new OcspBasicResponse($this->ocspResponse['responseBytes']['response']);
    }
}
