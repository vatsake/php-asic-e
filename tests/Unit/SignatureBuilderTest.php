<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Container\Signature\SignatureBuilder;
use Vatsake\AsicE\Container\Signature\SignatureXml;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Crypto\SignAlg;
use Vatsake\AsicE\Exceptions\InvalidCertificateException;

class SignatureBuilderTest extends TestCase
{
    private const TEST_TRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.crt';

    private function sampleFileDigests(): array
    {
        return [
            'alpha.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'alpha', true))],
            'beta.bin'  => [DigestAlg::SHA256, base64_encode(hash('sha256', str_repeat('B', 10), true))],
        ];
    }

    public function testSetInvalidCertificate()
    {
        $builder = new SignatureBuilder($this->sampleFileDigests());
        $this->expectException(InvalidCertificateException::class);
        $builder->setSigner('invalid certificate');
        $builder->getDataToBeSigned();
    }

    public function testGetDataToBeSigned(): void
    {
        $builder = new SignatureBuilder($this->sampleFileDigests());
        $builder->setSigner(file_get_contents(self::TEST_TRUSTED_X509_PATH))
            ->setSignatureAlg(SignAlg::ECDSA_SHA3_256);

        $b64 = $builder->getDataToBeSigned();

        $this->assertIsString($b64);
        $raw = base64_decode($b64, true);
        $this->assertNotFalse($raw, 'Result must be valid base64');
        $this->assertSame(32, strlen($raw), 'sha3-256 produces 32 bytes');
    }

    public function testSignedPropertiesDigestAlgInXml(): void
    {
        $builder = new SignatureBuilder($this->sampleFileDigests());
        $builder->setSigner(file_get_contents(self::TEST_TRUSTED_X509_PATH))
            ->setSignatureAlg(SignAlg::ECDSA_SHA3_256)
            ->setSignedPropertiesDigestAlg(DigestAlg::SHA512);

        // Trigger XML creation
        $builder->getDataToBeSigned();

        // Inspect resulting XML for signed-properties digest method
        $xml = $builder->toXml();
        $sigXml = new SignatureXml($xml);

        $this->assertSame(DigestAlg::SHA512, $sigXml->getSignedPropertiesDigestMethod());
    }

    public function testSerializeUnserializePreservesData(): void
    {
        $fileDigests = $this->sampleFileDigests();
        $builder = new SignatureBuilder($fileDigests);
        $builder->setSigner(file_get_contents(self::TEST_TRUSTED_X509_PATH))
            ->setSignatureAlg(SignAlg::ECDSA_SHA3_384)
            ->setSignedPropertiesDigestAlg(DigestAlg::SHA384);

        $xmlBefore = $builder->toXml();

        $serialized = serialize($builder);
        /** @var SignatureBuilder $restored */
        $restored = unserialize($serialized);

        $this->assertInstanceOf(SignatureBuilder::class, $restored);
        $this->assertSame($xmlBefore, $restored->toXml());
        $this->assertSame(SignAlg::ECDSA_SHA3_384, $restored->getSignatureAlg());
        $this->assertSame(file_get_contents(self::TEST_TRUSTED_X509_PATH), $restored->getSigner());
    }
}
