<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container;

use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Exceptions\ZipException;
use ZipArchive;

class ZipWriter
{
    private ZipArchive $zip;

    public function __construct(private readonly string $zipPath)
    {
        $this->zip = new ZipArchive();
    }

    public static function createNew(string $zipPath): self
    {
        self::assertCreateNewPossible($zipPath);
        $self = new self($zipPath);

        $self->withWriteZip(function (ZipArchive $zip) {
            if ($zip->addFromString('mimetype', 'application/vnd.etsi.asic-e+zip') !== true) {
                throw new ZipException('Failed to add mimetype.');
            }
            if ($zip->setCompressionName('mimetype', ZipArchive::CM_STORE) !== true) {
                throw new ZipException('Failed to store mimetype without compression.');
            }
        }, ZipArchive::CREATE | ZipArchive::OVERWRITE);

        return $self;
    }

    public static function openExisting(string $zipPath): self
    {
        self::assertOpenExistingPossible($zipPath);
        return new self($zipPath);
    }

    public function addFile(string $name, string $contents): void
    {
        $this->withWriteZip(function (ZipArchive $zip) use ($name, $contents) {
            if ($zip->addFromString($name, $contents) !== true) {
                throw new ZipException("Failed to add file '{$name}'.");
            }
            if ($zip->setCompressionName($name, ZipArchive::CM_DEFLATE) !== true) {
                throw new ZipException("Failed to compress file '{$name}'.");
            }
        }, ZipArchive::CREATE);
    }

    public function getSignatureFiles(): array
    {
        return $this->withReadZip(function (ZipArchive $zip) {
            $files = [];
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if ($stat === false) {
                    throw new ZipException("Failed to stat index {$i}.");
                }
                $name = $stat['name'];

                // Skip directories and the ASiC manifest
                if (str_ends_with($name, '/')) {
                    continue;
                }
                if (str_ends_with($name, 'manifest.xml')) {
                    continue;
                }
                if (str_starts_with($name, 'META-INF/')) {
                    $files[] = $name;
                }
            }
            return $files;
        });
    }

    public function fileExists(string $path): bool
    {
        return $this->withReadZip(fn(ZipArchive $zip) => $zip->locateName($path) !== false);
    }

    /**
     * @return string|null Returns file contents or null if file does not exist
     */
    public function getFile(string $path): ?string
    {
        return $this->withReadZip(function (ZipArchive $zip) use ($path) {
            $data = $zip->getFromName($path);
            return $data === false ? null : $data;
        });
    }

    /**
     * @return array<string, array{0: DigestAlg, 1: string}>
     */
    public function getSignedFileDigests(DigestAlg $digestAlg): array
    {
        return $this->withReadZip(function (ZipArchive $zip) use ($digestAlg) {
            $rootFiles = [];
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if ($stat === false) {
                    throw new ZipException("Failed to stat index {$i}.");
                }
                $name = $stat['name'];

                // Only root-level files, excluding 'mimetype'
                if (!str_contains($name, '/') && $name !== 'mimetype') {
                    $rootFiles[$name] = [$digestAlg, $this->hashEntryBase64($zip, $name, $digestAlg)];
                }
            }
            return $rootFiles;
        });
    }

    public function getSignedFileAlg(DigestAlg $digestAlg, $name): string
    {
        return $this->withReadZip(fn(ZipArchive $zip) => $this->hashEntryBase64($zip, $name, $digestAlg));
    }

    private function hashEntryBase64(ZipArchive $zip, string $name, DigestAlg $alg): string
    {
        // Prefer streaming to avoid loading big files into memory
        $stream = $zip->getStream($name);
        if ($stream === false) {
            $data = $zip->getFromName($name);
            if ($data === false) {
                throw new ZipException("Cannot read entry '{$name}'.");
            }
            return base64_encode(hash($alg->value, $data, true));
        }

        try {
            $ctx = hash_init($alg->value);
            while (!feof($stream)) {
                $chunk = fread($stream, 8192);
                if ($chunk === false) {
                    throw new ZipException("Failed reading stream for '{$name}'.");
                }
                hash_update($ctx, $chunk);
            }
            return base64_encode(hash_final($ctx, true));
        } finally {
            fclose($stream);
        }
    }

    private function withReadZip(callable $cb)
    {
        return $this->withZip($cb, ZipArchive::RDONLY);
    }

    private function withWriteZip(callable $cb, int $flags)
    {
        return $this->withZip($cb, $flags);
    }

    private function withZip(callable $cb, int $flags)
    {
        if ($this->zip->open($this->zipPath, $flags) !== true) {
            throw new ZipException("Cannot open {$this->zipPath}");
        }

        try {
            return $cb($this->zip);
        } finally {
            $this->zip->close();
        }
    }

    private static function assertOpenExistingPossible(string $path): void
    {
        if (!is_file($path)) {
            throw new ZipException("Zip does not exist: {$path}");
        }
        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::RDONLY) !== true) {
            throw new ZipException("Cannot open existing zip: {$path}");
        }
        $zip->close();
    }

    private static function assertCreateNewPossible(string $path): void
    {
        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new ZipException("Cannot create/overwrite {$path}");
        }
        $zip->close();
    }
}
