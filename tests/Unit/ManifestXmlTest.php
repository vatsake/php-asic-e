<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use DOMDocument;
use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Container\ManifestXml;

class ManifestXmlTest extends TestCase
{
    private const NS_MANIFEST = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';

    private function loadXml(string $xml): DOMDocument
    {
        $dom = new DOMDocument();
        $this->assertTrue($dom->loadXML($xml), 'Generated XML should be well-formed');
        return $dom;
    }

    public function testCreateBase()
    {
        $manifestXml = new ManifestXml();
        $dom = $this->loadXml($manifestXml->toXml());

        $root = $dom->documentElement;
        $this->assertSame(self::NS_MANIFEST, $root->namespaceURI);
        $this->assertSame('1.2', $root->getAttribute('manifest:version'));

        $fileEntries = $root->getElementsByTagName('file-entry');
        $this->assertSame(1, $fileEntries->count());
        $this->assertSame('/', $fileEntries->item(0)->getAttribute('manifest:full-path'));
        $this->assertSame('application/vnd.etsi.asic-e+zip', $fileEntries->item(0)->getAttribute('manifest:media-type'));
    }

    public function testAddFileManifestEntry(): void
    {
        $manifestXml = new ManifestXml();
        $manifestXml->addFileManifest('test.txt', 'text/plain');

        $dom = $this->loadXml($manifestXml->toXml());

        $fileEntries = $dom->getElementsByTagName('file-entry');
        $this->assertSame(2, $fileEntries->count());
        $this->assertSame('test.txt', $fileEntries->item(1)->getAttribute('manifest:full-path'));
        $this->assertSame('text/plain', $fileEntries->item(1)->getAttribute('manifest:media-type'));
    }
}
