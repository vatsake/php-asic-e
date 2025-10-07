<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Api\Ocsp\OcspRequest;
use Vatsake\AsicE\Crypto\DigestAlg;

class OcspRequestTest extends TestCase
{
    private const TEST_CA_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'testCA.crt';
    private const TEST_TRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.crt';

    public function testBuildsDerBody_withCorrectFields(): void
    {
        $signerPem = file_get_contents(self::TEST_TRUSTED_X509_PATH);
        $issuerPem = file_get_contents(self::TEST_CA_PATH);

        $req = new OcspRequest(
            url: 'http://ocsp.example.invalid/',
            signerCertificate: $signerPem,
            issuerCertificate: $issuerPem,
            digest: DigestAlg::SHA256
        );

        $der = $req->getBody();
        $this->assertEquals('http://ocsp.example.invalid/', $req->getUrl());
        $this->assertIsString($der);
        $this->assertNotEmpty($der);
    }
}
