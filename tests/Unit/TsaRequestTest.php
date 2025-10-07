<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Reflection;
use Vatsake\AsicE\Api\Tsa\TsaRequest;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Crypto\DigestAlg;

class TsaRequestTest extends TestCase
{

    public function testGetUrlAndNonce(): void
    {
        $url = 'https://tsa.example.test/ts';
        $dataToSign = '<SigValue>abc</SigValue>';
        $req = new TsaRequest($url, $dataToSign);

        $this->assertSame($url, $req->getUrl());
        $this->assertNotNull($req->getNonce());
        $this->assertTrue($req->getNonce()->toString() !== '');
    }

    public function testGetBodyEncodesHashAndFields(): void
    {
        $url = 'https://tsa.example.test/ts';
        $payload = 'hello-xml-signature';
        $req = new TsaRequest($url, $payload, DigestAlg::SHA256);

        $ref = new \ReflectionClass(TsaRequest::class);
        $map = $ref->getConstant('TSQ_REQUEST');

        $der = $req->getBody();
        $decoded = Asn1Helper::decode($der, $map);

        $this->assertSame('1', (string) $decoded['version']);

        $this->assertSame(DigestAlg::SHA256->getOid(), $decoded['messageImprint']['hashAlgorithm']['algorithm']);
        $this->assertSame(hash('sha256', $payload, true), $decoded['messageImprint']['hashedMessage']);

        $this->assertTrue($decoded['certReq']);
        $this->assertArrayHasKey('nonce', $decoded);
        $this->assertSame(0, $req->getNonce()->compare($decoded['nonce']));

        $this->assertArrayNotHasKey('reqPolicy', $decoded);
        $this->assertArrayNotHasKey('extensions', $decoded);
    }
}
