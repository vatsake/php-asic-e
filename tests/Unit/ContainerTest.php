<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Reflection;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Container\Signature\FinalizedSignature;
use Vatsake\AsicE\Container\Signature\SignatureBuilder;
use Vatsake\AsicE\Container\Signature\SignatureXml;
use Vatsake\AsicE\Container\UnsignedContainer;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Exceptions\EmptyContainerException;
use Vatsake\AsicE\Validation\Lotl;
use ZipArchive;

class ContainerTest extends TestCase
{
    private const TEST_TRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.crt';
    private const SIGNED_CONTAINER_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'TestFiles' . DIRECTORY_SEPARATOR . 'signed.asice';

    private function makeUnsignedContainerWithFiles(array $files): string
    {
        $tmpPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('', true) . '.asice';

        $uc = new UnsignedContainer();
        foreach ($files as $name => $contents) {
            $uc->addFile($name, $contents);
        }
        $uc->build($tmpPath);
        return $tmpPath;
    }

    public function testCreateSignatureReturnsBuilderAndDataToBeSigned()
    {
        $zipPath = $this->makeUnsignedContainerWithFiles([
            'a.txt' => 'AAA',
        ]);

        try {
            $container = new Container($zipPath);
            $builder = $container->createSignature();
            $this->assertInstanceOf(SignatureBuilder::class, $builder);

            // Use repo-provided PEM to build signed info offline (no TSA/OCSP here)
            $pem = file_get_contents(self::TEST_TRUSTED_X509_PATH);
            $dataToBeSigned = $builder
                ->setSigner($pem)
                ->getDataToBeSigned();

            $this->assertIsString($dataToBeSigned);
            $this->assertNotSame('', $dataToBeSigned);
            $this->assertNotFalse(base64_decode($dataToBeSigned, true), 'Should be base64-encoded');
        } finally {
            if (is_file($zipPath)) {
                unlink($zipPath);
            }
        }
    }

    public function testAddSignatureCreatesUniqueNames(): void
    {
        $zipPath = $this->makeUnsignedContainerWithFiles([
            'doc1.txt' => 'hello',
        ]);

        try {
            $container = new Container($zipPath);

            // Minimal signatures: we only need to supply XML; we’re not validating here.
            $sigXml1 = new SignatureXml(); // bare skeleton is enough for addSignature
            $sig1 = new FinalizedSignature($sigXml1, [
                'doc1.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'hello', true))]
            ]);
            $container->addSignature($sig1);

            $sigXml2 = new SignatureXml();
            $sig2 = new FinalizedSignature($sigXml2, [
                'doc1.txt' => [DigestAlg::SHA256, base64_encode(hash('sha256', 'hello', true))]
            ]);
            $container->addSignature($sig2);

            $za = new ZipArchive();
            $za->open($zipPath, ZipArchive::RDONLY);
            $this->assertNotFalse($za->locateName('META-INF/signatures0.xml'), 'First signature file should exist');
            $this->assertNotFalse($za->locateName('META-INF/signatures1.xml'), 'Second signature file should exist');
            $za->close();
        } finally {
            if (is_file($zipPath)) {
                unlink($zipPath);
            }
        }
    }

    public function testCreateSignatureOnEmptyDatafilesContainer(): void
    {
        $containerPath = $this->makeUnsignedContainerWithFiles([]);
        try {
            $container = new Container($containerPath);
            $this->expectException(EmptyContainerException::class);
            $container->createSignature();
        } finally {
            if (is_file($containerPath)) {
                unlink($containerPath);
            }
        }
    }

    public function testGetSignatures(): void
    {
        $container = new Container(self::SIGNED_CONTAINER_PATH);
        $container->getSignatures();
        $this->assertCount(1, $container->getSignatures());
        $sig = $container->getSignatures()[0];
        $this->assertInstanceOf(FinalizedSignature::class, $sig);
    }
}
