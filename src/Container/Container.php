<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container;

use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Container\Signature\FinalizedSignature;
use Vatsake\AsicE\Container\Signature\SignatureBuilder;
use Vatsake\AsicE\Container\Signature\SignatureXml;
use Vatsake\AsicE\Exceptions\EmptyContainerException;

final class Container
{
    private ZipWriter $writer;

    private function __construct(string $containerPath)
    {
        $this->writer = ZipWriter::openExisting($containerPath);
    }

    public static function open(string $containerPath): self
    {
        return new self($containerPath);
    }

    /**
     * Prepares a signature object
     *
     * Add finalized signature back to container using addSignature method after user has done signing
     */
    public function createSignature(): SignatureBuilder
    {
        $fileDigests = $this->writer->getSignedFileDigests(DigestAlg::SHA256);
        if (empty($fileDigests)) {
            throw new EmptyContainerException('Cannot create signature: container has no files to sign');
        }

        return new SignatureBuilder($fileDigests);
    }

    public function addSignature(FinalizedSignature $signature)
    {
        $i = 0;
        $uniqueSignatureName = "META-INF/signatures{$i}.xml";
        while ($this->writer->fileExists($uniqueSignatureName)) {
            $i++;
            $uniqueSignatureName = "META-INF/signatures{$i}.xml";
        }

        $this->writer->addFile($uniqueSignatureName, $signature->toXml());
    }

    /**
     * @return FinalizedSignature[]
     */
    public function getSignatures(): array
    {
        $signatures = [];
        foreach ($this->writer->getSignatureFiles() as $filename) {
            $sigXml = new SignatureXml($this->writer->getFile($filename));

            $fileDigests = $sigXml->getFileDigestMethods();
            foreach ($fileDigests as $filename => $values) {
                $fileDigests[$filename] = [$values[0], $this->writer->getSignedFileAlg($values[0], $filename)];
            }

            $signatures[] = new FinalizedSignature($sigXml, $fileDigests);
        }
        return $signatures;
    }

    /**
     * @return array{index: int, valid: bool, errors: ValidationResult[]}
     */
    public function validateSignatures(): array
    {
        $results = [];
        foreach ($this->getSignatures() as $index => $signature) {
            $isValid = $signature->isValid();
            $results[] = [
                'index' => $index,
                'valid' => $isValid ? true : false,
                'errors' => $isValid ? [] : $signature->getValidationErrors(),
            ];
        }
        return $results;
    }
}
