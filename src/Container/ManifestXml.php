<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container;

use DOMDocument;

class ManifestXml
{
    private DOMDocument $xml;

    public function __construct()
    {
        $this->xml = new DOMDocument('1.0', 'UTF-8');
        $this->createBase();
    }

    public function toXml(): string
    {
        return $this->xml->saveXML();
    }

    public function addFileManifest(string $path, string $mediaType)
    {
        $fileManifest = $this->xml->createElement('manifest:file-entry');
        $fileManifest->setAttribute('manifest:full-path', $path);
        $fileManifest->setAttribute('manifest:media-type', $mediaType);
        $this->xml->documentElement->appendChild($fileManifest);
    }

    private function createBase()
    {
        $this->xml->formatOutput = true;

        $root = $this->xml->createElementNS('urn:oasis:names:tc:opendocument:xmlns:manifest:1.0', 'manifest:manifest');
        $root->setAttribute('manifest:version', '1.2');
        $this->xml->appendChild($root);

        $this->addFileManifest('/', 'application/vnd.etsi.asic-e+zip');
    }
}
