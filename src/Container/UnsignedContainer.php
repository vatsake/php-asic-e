<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container;

use Vatsake\AsicE\Exceptions\ContainerAlreadyFinalized;

/**
 * Creates an ASiC-E container without any signatures
 */
final class UnsignedContainer
{
    private bool $sealed = false;
    private array $files = [];

    public function addFile(string $name, string $contents): self
    {
        $this->checkIfContainerIsSealed();
        $this->files[$name] = $contents;
        return $this;
    }

    public function getFiles(): array
    {
        return $this->files;
    }

    public function build($path): Container
    {
        $this->checkIfContainerIsSealed();

        $writer = ZipWriter::createNew($path);
        foreach ($this->files as $name => $contents) {
            $writer->addFile($name, $contents);
        }

        $manifestXml = new ManifestXml();
        foreach ($this->files as $name => $contents) {
            $manifestXml->addFileManifest($name, 'application/octet-stream');
        }
        $writer->addFile('META-INF/manifest.xml', $manifestXml->toXml());

        $this->sealed = true;

        return new Container($path);
    }

    private function checkIfContainerIsSealed()
    {
        if ($this->sealed) {
            throw new ContainerAlreadyFinalized();
        }
    }
}
