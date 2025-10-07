<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use DateTimeImmutable;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Api\Ocsp\OcspRequest;
use Vatsake\AsicE\Api\Ocsp\OcspResponse;
use Vatsake\AsicE\Api\Ocsp\OcspBasicResponse as ApiOcspBasicResponse;
use Vatsake\AsicE\ASN1\OcspBasicResponse;
use Vatsake\AsicE\ASN1\OcspResponse as ASN1OcspResponse;;

use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Exceptions\Asn1Exception;
use Vatsake\AsicE\Exceptions\OcspException;

class OcspResponseTest extends TestCase
{
    private function basicResponseDer(): string
    {
        $now = gmdate('YmdHis\Z');
        $basic = [
            'tbsResponseData' => [
                'responderID' => [
                    'byKey' => random_bytes(20),
                ],
                'producedAt' => $now,
                'responses' => [
                    [
                        'certID' => [
                            'hashAlgorithm' => [
                                'algorithm'  => '1.3.14.3.2.26',
                                'parameters' => ['null' => ''],
                            ],
                            'issuerNameHash' => random_bytes(20),
                            'issuerKeyHash'  => random_bytes(20),
                            'serialNumber'   => 1,
                        ],
                        'certStatus' => [
                            'unknown' => '',
                        ],
                        'thisUpdate' => $now,
                    ],
                ],
                'responseExtensions' => [],
            ],
            'signatureAlgorithm' => [
                'algorithm'  => 'sha256WithRSAEncryption',
                'parameters' => ['null' => ''],
            ],
            'signature' => "\x00" . random_bytes(256),
        ];

        return Asn1Helper::encode($basic, OcspBasicResponse::MAP);
    }

    public function testSuccessfulResponseGetTokenGetBasicResponse(): void
    {
        $der = Asn1Helper::encode([
            'responseStatus' => 'successful',
            'responseBytes' => [
                'responseType' => '1.3.6.1.5.5.7.48.1.1',
                'response' => $this->basicResponseDer(),
            ],
        ], ASN1OcspResponse::MAP);

        $resp = new OcspResponse($der);
        $this->assertSame(base64_encode($der), $resp->getToken());
        $this->assertInstanceOf(ApiOcspBasicResponse::class, $resp->getBasicResponse());
    }

    public function testInvalidResponseData(): void
    {
        $this->expectException(Asn1Exception::class);
        Asn1Helper::encode([
            'responseStatus' => 'successful',
            'responseStatus1' => 'successful',
            'responseStatus2' => 'successful',
            'responseBytes' => [
                'responseType' => '1.3.6.1.5.5.7.48.1.1',
            ],
        ], ASN1OcspResponse::MAP);
    }

    public function testInvalidResponseStatus(): void
    {
        $der = Asn1Helper::encode([
            'responseStatus' => 'sigRequired',
            'responseBytes' => [
                'responseType' => '1.3.6.1.5.5.7.48.1.1',
                'response' => $this->basicResponseDer(),
            ],
        ], ASN1OcspResponse::MAP);
        $this->expectException(OcspException::class);
        new OcspResponse($der);
    }

    public function testInvalidResponseType(): void
    {
        $der = Asn1Helper::encode([
            'responseStatus' => 'successful',
            'responseBytes' => [
                'responseType' => '1.3.6.1.5.5.7.48.1.2', // Not basic OCSP response
                'response' => $this->basicResponseDer(),
            ],
        ], ASN1OcspResponse::MAP);
        $this->expectException(OcspException::class);
        $resp = new OcspResponse($der);
        $resp->getBasicResponse();
    }

    public function testOcspBasicResponseGetters(): void
    {
        $der = Asn1Helper::encode([
            'responseStatus' => 'successful',
            'responseBytes' => [
                'responseType' => '1.3.6.1.5.5.7.48.1.1',
                'response' => $this->basicResponseDer(),
            ],
        ], ASN1OcspResponse::MAP);

        $resp = new OcspResponse($der);
        $basicResponse = $resp->getBasicResponse();

        $this->assertInstanceOf(DigestAlg::class, $basicResponse->getIssuerPublicKeyHashAlg());
        $this->assertNotEquals("", $basicResponse->getSignerSerialNumber());
        $this->assertInstanceOf(DateTimeImmutable::class, $basicResponse->getStatusIssuedAt());
        $this->assertInstanceOf(DateTimeImmutable::class, $basicResponse->getResponseProducedAt());
        $this->assertNotEquals("", $basicResponse->getSignature());
        $this->assertNotEquals("", $basicResponse->getSignatureAlgorithm());
    }
}
