<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use DateTimeImmutable;
use DOMDocument;
use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Container\Signature\SignatureXml;
use Vatsake\AsicE\Crypto\CanonicalizationMethod;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Crypto\SignAlg;

class SignatureXmlTest extends TestCase
{
    private const TEST_TRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.crt';

    private function parseSerialFromPem(string $pem): string
    {
        $parsed = openssl_x509_parse($pem);
        $this->assertIsArray($parsed);
        $this->assertArrayHasKey('serialNumber', $parsed);
        return Utils::serialToNumber($parsed['serialNumber']);
    }

    public function testBaseStructure(): void
    {
        $sig = new SignatureXml();
        $xml = $sig->toXml();

        $dom = new DOMDocument();
        $this->assertTrue($dom->loadXML($xml));

        $this->assertSame(1, $dom->getElementsByTagName('XAdESSignatures')->length);
        $this->assertSame(1, $dom->getElementsByTagName('Signature')->length);
        $this->assertSame(1, $dom->getElementsByTagName('Signature')->length);
    }

    public function testCreateSignedPropertiesPopulatesSignerDataAndSignerDigest(): void
    {
        $pem = file_get_contents(self::TEST_TRUSTED_X509_PATH);
        $digest = base64_encode(hash('sha256', base64_decode(Utils::removePemFormatting($pem)), true));
        $sn = $this->parseSerialFromPem($pem);

        $sig = new SignatureXml();
        $sig->createSignedProperties($pem, 2);
        $xml = $sig->toXml();

        $this->assertStringContainsString($digest, $xml);
        $this->assertSame($sn, $sig->getSignerSerialNumber());
        $this->assertStringContainsString(DigestAlg::SHA256->getUrl(), $xml);

        // Signing time is an RFC3339 timestamp near "now"
        $t = $sig->getSigningTime();
        $this->assertInstanceOf(DateTimeImmutable::class, $t);
        $this->assertLessThan(120, abs($t->getTimestamp() - time()), 'Signing time should be close to now');
    }

    public function testCreateSignedInfoAddsFileReferencesAndSignedPropsRefAndMethodsReflectChoices(): void
    {
        $pem = file_get_contents(self::TEST_TRUSTED_X509_PATH);

        // Prepare SignedProperties and two file digests (one with an encoded filename)
        $sig = new SignatureXml();
        $sig->createSignedProperties($pem, 2);

        $fileDigests = [
            'alpha.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'alpha', true))],
            'with space.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'space', true))],
        ];

        // Choose ECDSA_SHA256 for sign method and SHA384 for signed-props digest
        $sig->createSignedInfo($fileDigests, SignAlg::ECDSA_SHA256, DigestAlg::SHA384);

        // getSignedInfoSignMethod should reflect the SignAlg we chose
        $this->assertSame(SignAlg::ECDSA_SHA256, $sig->getSignedInfoSignMethod());

        // File digests returned should match inputs and filenames should be decoded
        $returned = $sig->getFileDigestMethods();
        $this->assertArrayHasKey('alpha.txt', $returned);
        $this->assertArrayHasKey('with space.txt', $returned);

        [$alg1, $hash1] = $returned['alpha.txt'];
        $this->assertSame(DigestAlg::SHA256, $alg1);
        $this->assertSame(base64_encode(hash('sha256', 'alpha', true)), $hash1);

        [$alg2, $hash2] = $returned['with space.txt'];
        $this->assertSame(DigestAlg::SHA256, $alg2);
        $this->assertSame(base64_encode(hash('sha256', 'space', true)), $hash2);

        // SignedProperties digest method is the SHA384 we passed
        $this->assertSame(DigestAlg::SHA384, $sig->getSignedPropertiesDigestMethod());

        // The SignedProperties digest value matches the canonicalized content hashed with SHA384
        $canon = $sig->getSignedPropertiesCanonicalized(true);
        $expectedSpDigest = base64_encode(hash('sha384', $canon, true));
        $this->assertSame($expectedSpDigest, $sig->getSignedPropertiesDigest());

        // SignedInfo canonicalization returns a non-empty canonical string
        $canonSi = $sig->getSignedInfoCanonicalized(true);
        $this->assertIsString($canonSi);
        $this->assertNotSame('', $canonSi);
    }

    public function testCanonicalizationMethod_defaults_and_tryFromUrl_normalization(): void
    {
        $pem = file_get_contents(self::TEST_TRUSTED_X509_PATH);
        $fileDigests = [
            'alpha.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'alpha', true))],
            'with space.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'space', true))],
        ];
        $sig = new SignatureXml();

        $sig->createSignedProperties($pem, 2);
        $sig->createSignedInfo($fileDigests, SignAlg::ECDSA_SHA256, DigestAlg::SHA384);

        $canon = $sig->getSignedInfoCanonicalized(true);
        $this->assertIsString($canon);
        $this->assertNotSame('', $canon);

        // Ensure CanonicalizationMethod::tryFromUrl matches base without '#'
        $cm = CanonicalizationMethod::tryFromUrl('http://www.w3.org/2001/10/xml-exc-c14n#');
        $this->assertTrue($cm->exclusive());
        $this->assertFalse($cm->withComments());

        // Same method but without trailing '#'
        $cm2 = CanonicalizationMethod::tryFromUrl('http://www.w3.org/2001/10/xml-exc-c14n');
        $this->assertSame($cm, $cm2);
    }
}
