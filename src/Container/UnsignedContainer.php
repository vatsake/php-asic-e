<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container;

use Psr\Log\LoggerInterface;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Exceptions\ContainerAlreadyFinalized;

/**
 * Creates an ASiC-E container without any signatures
 */
final class UnsignedContainer
{
    private ?LoggerInterface $logger = null;
    private bool $sealed = false;
    private array $files = [];

    public function __construct()
    {
        $this->logger = AsiceConfig::getLogger();
    }

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
        $startedAt = microtime(true);
        $this->checkIfContainerIsSealed();

        $this->logger?->info('unsigned_container.build.start', [
            'fileCount' => count($this->files),
        ]);

        $writer = ZipWriter::createNew($path);
        foreach ($this->files as $name => $contents) {
            $this->logger?->debug('unsigned_container.build.adding_file', [
                'name' => $name,
                'size' => strlen($contents),
            ]);
            $writer->addFile($name, $contents);
        }

        $manifestXml = new ManifestXml();
        foreach ($this->files as $name => $contents) {
            $manifestXml->addFileManifest($name, 'application/octet-stream');
        }
        $writer->addFile('META-INF/manifest.xml', $manifestXml->toXml());

        $this->sealed = true;

        $this->logger?->info('unsigned_container.build.completed', [
            'fileCount' => count($this->files),
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return Container::open($path);
    }

    private function checkIfContainerIsSealed()
    {
        if ($this->sealed) {
            throw new ContainerAlreadyFinalized();
        }
    }
}
