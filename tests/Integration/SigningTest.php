<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Integration;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\EcdsaSigValue;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Container\Signature\FinalizedSignature;
use Vatsake\AsicE\Container\Signature\SignatureBuilder;
use Vatsake\AsicE\Container\UnsignedContainer;
use Vatsake\AsicE\Crypto\SignAlg;
use Vatsake\AsicE\Validation\Lotl;

class SigningTest extends TestCase
{
    // This container has a valid TEST signature (TSL doesn't trust)
    private const SIGNED_CONTAINER_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'TestFiles' . DIRECTORY_SEPARATOR . 'signed.asice';
    private const TEST_CA_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'testCA.crt';
    private const TEST_TRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.crt';
    private const TEST_TRUSTED_X509_KEY_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.key';

    public function testValidateSignaturesAllValid(): void
    {
        $ca = Utils::stripPemHeaders(file_get_contents(self::TEST_CA_PATH));
        AsiceConfig::getInstance()->fromArray([
            'countryCode' => 'LT',
            'lotl' => [$ca]
        ]);

        $container = Container::open(self::SIGNED_CONTAINER_PATH);
        $results = $container->validateSignatures();

        $this->assertNotEmpty($results, 'Expected at least one validation result');
        foreach ($results as $result) {
            $result['errors'] = array_filter($result['errors'], fn($e) => !str_contains($e->reason, 'trusted CA')); // Ignore trust errors in tests
            $result['valid'] = empty($result['errors']);
            $this->assertArrayHasKey('index', $result);
            $this->assertArrayHasKey('valid', $result);
            $this->assertTrue($result['valid'], 'Expected signature at index ' . $result['index'] . ' to be valid. Errors: ' . json_encode($result['errors']));
        }
    }

    public function testCreateValidContainer(): void
    {
        $ca = Utils::stripPemHeaders(file_get_contents(self::TEST_CA_PATH));
        AsiceConfig::getInstance()->fromArray([
            'countryCode' => 'LT',
            'lotl' => [$ca],
            'tsaUrl' => 'https://freetsa.org/tsr',
            'ocspUrl' => 'http://demo.sk.ee/ocsp'
        ]);

        $tempPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-container-1.asice';
        $unsignedContainer = new UnsignedContainer();
        $unsignedContainer->addFile('test.txt', 'This is a test file.');
        $container = $unsignedContainer->build($tempPath);
        $this->assertFileExists($tempPath);

        $signatureBuilder = $container->createSignature();
        $signatureBuilder->setSigner(file_get_contents(self::TEST_TRUSTED_X509_PATH))
            ->setSignatureAlg(SignAlg::RSA_SHA256);
        $dataToSign = $signatureBuilder->getDataToBeSigned(true);
        $serialized = serialize($signatureBuilder);

        // --- User signs data
        $pkeyid = openssl_pkey_get_private(file_get_contents(self::TEST_TRUSTED_X509_KEY_PATH));
        $result = openssl_sign($dataToSign, $signatureValue, $pkeyid, OPENSSL_ALGO_SHA256);
        $this->assertTrue($result, 'Signing failed');
        // --- User signs data

        /** @var SignatureBuilder */
        $signatureBuilder = unserialize($serialized);
        $signature = $signatureBuilder->finalize(base64_encode($signatureValue));
        $this->assertInstanceOf(FinalizedSignature::class, $signature);

        $container->addSignature($signature);
        $signatures = $container->getSignatures();
        $this->assertCount(1, $signatures);

        $signatures[0]->isValid();
        $errors = $signatures[0]->getValidationErrors();

        $this->assertEquals(3, count($errors), 'Expected three validation errors (trust anchor and OCSP): ' . json_encode($errors) . ')');
        unlink($tempPath);
    }
}
