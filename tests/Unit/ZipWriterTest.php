<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Container\ZipWriter;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Exceptions\ZipException;
use ZipArchive;

class ZipWriterTest extends TestCase
{

    private function tempZipPath(): string
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'asice-zip-' . uniqid('', true);
        return $base . '.zip';
    }

    public function testCreateZip()
    {
        $tempPath = $this->tempZipPath();

        try {
            ZipWriter::createNew($tempPath);
            $this->assertFileExists($tempPath);
        } finally {
            unlink($tempPath);
        }
    }

    public function testMimetypeIsStoredAndUncompressed(): void
    {
        $tempPath = $this->tempZipPath();

        try {
            $zip = ZipWriter::createNew($tempPath);

            $this->assertSame(
                'application/vnd.etsi.asic-e+zip',
                $zip->getFile('mimetype')
            );

            // Verify compression method is STORE
            $za = new ZipArchive();
            $this->assertTrue($za->open($tempPath, ZipArchive::RDONLY));
            $stat = $za->statName('mimetype');
            $this->assertArrayHasKey('comp_method', $stat);
            $this->assertSame(ZipArchive::CM_STORE, $stat['comp_method']);
            $za->close();
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testAddFile()
    {
        try {
            $tempPath = $this->tempZipPath();
            $zip = ZipWriter::createNew($tempPath);
            $textContents = 'This is a test file.';
            $zip->addFile('test.txt', $textContents);
            $this->assertEquals($textContents, $zip->getFile('test.txt'));
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testArchiveClosedBetweenCommands()
    {
        $tempPath = $this->tempZipPath();

        try {
            $reflectionClass = new \ReflectionClass(ZipWriter::class);
            $reflectionClass->getProperty('zip')->setAccessible(true);

            $zip = ZipWriter::createNew($tempPath);
            $this->assertEquals('', $reflectionClass->getProperty('zip')->getValue($zip)->filename);
            $textContents = 'This is a test file.';
            $zip->addFile('test.txt', $textContents);
            $this->assertEquals('', $reflectionClass->getProperty('zip')->getValue($zip)->filename);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testGetSignedFileDigests(): void
    {
        $tempPath = $this->tempZipPath();

        try {
            $zip = ZipWriter::createNew($tempPath);
            $zip->addFile('A.txt', 'AAA');
            $zip->addFile('B.bin', str_repeat('B', 10));
            // Files under META-INF should not be included by getSignedFileDigests
            $zip->addFile('META-INF/manifest.xml', '12345');
            $zip->addFile('META-INF/signatures0.xml', '123456');

            $digests = $zip->getSignedFileDigests(DigestAlg::SHA256);

            // Only root files except 'mimetype' should be present
            $this->assertArrayHasKey('A.txt', $digests);
            $this->assertArrayHasKey('B.bin', $digests);
            $this->assertArrayNotHasKey('mimetype', $digests);
            $this->assertArrayNotHasKey('META-INF/manifest.xml', $digests);
            $this->assertArrayNotHasKey('META-INF/signatures0.xml', $digests);

            [$algA, $hashA] = $digests['A.txt'];
            $this->assertSame(DigestAlg::SHA256, $algA);
            $this->assertSame(base64_encode(hash('sha256', 'AAA', true)), $hashA);

            [$algB, $hashB] = $digests['B.bin'];
            $this->assertSame(DigestAlg::SHA256, $algB);
            $this->assertSame(base64_encode(hash('sha256', str_repeat('B', 10), true)), $hashB);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testGetSignatureFiles_collectsMetaInfNonManifestFiles(): void
    {
        $tempPath = $this->tempZipPath();

        try {
            $zip = ZipWriter::createNew($tempPath);
            $zip->addFile('doc.txt', 'x');
            $zip->addFile('META-INF/manifest.xml', '123');
            $zip->addFile('META-INF/signatures0.xml', '123');
            $zip->addFile('META-INF/file.xml', '123');

            $signatureFiles = $zip->getSignatureFiles();

            // Should include META-INF files except manifest.xml; include subdirectory files
            $this->assertContains('META-INF/signatures0.xml', $signatureFiles);
            $this->assertContains('META-INF/file.xml', $signatureFiles);
            $this->assertNotContains('META-INF/manifest.xml', $signatureFiles);
            $this->assertNotContains('doc.txt', $signatureFiles);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testOpenExistingThrowsOnMissing(): void
    {
        $tempPath = $this->tempZipPath();

        $this->expectException(ZipException::class);
        ZipWriter::openExisting($tempPath);
    }

    public function testOpenLockedThrows(): void
    {
        $tempPath = $this->tempZipPath();

        try {
            $zip = new ZipArchive();
            $zip->open($tempPath, ZipArchive::CREATE);

            $this->expectException(ZipException::class);
            ZipWriter::openExisting($tempPath);
        } finally {
            $zip->close();
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testFileExists(): void
    {
        $tempPath = $this->tempZipPath();

        try {
            $zip = ZipWriter::createNew($tempPath);
            $zip->addFile('doc.txt', 'x');
            $this->assertTrue($zip->fileExists('doc.txt'));
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function testGetSingleFileDigest(): void
    {
        $tempPath = $this->tempZipPath();

        try {
            $zip = ZipWriter::createNew($tempPath);
            $zip->addFile('A.txt', 'AAA');

            $digest = $zip->getSignedFileAlg(DigestAlg::SHA256, 'A.txt');
            $this->assertSame(base64_encode(hash('sha256', 'AAA', true)), $digest);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
