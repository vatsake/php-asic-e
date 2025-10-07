<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Signature;

use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates that SignedInfo references contain the expected digest values for each data file.
 */
class FileDigestsValidator implements Validator
{
    /**
     * @param SignatureXml $xml
     * @param array<string, array{0: \Vatsake\AsicE\Crypto\DigestAlg, 1: string}> $realFileDigests needed for validation
     */
    public function __construct(private SignatureXml $xml, private array $realFileDigests)
    {
    }

    public function validate(): ValidationResult
    {
        $digestsInXml = $this->xml->getFileDigestMethods();

        foreach ($this->realFileDigests as $name => [$expectedAlg, $expectedDigest]) {
            if (!array_key_exists($name, $digestsInXml)) {
                return new ValidationResult(
                    false,
                    "Digest for signed data object \"$name\" is missing from the signature.",
                    [
                        'expectedDigest' => $expectedDigest,
                        'expectedDigestAlg' => $expectedAlg->value,
                    ],
                );
            }

            [$signatureAlg, $digestInSignature] = $digestsInXml[$name];

            if ($expectedDigest !== $digestInSignature) {
                return new ValidationResult(
                    false,
                    "Digest mismatch for signed data object \"$name\".",
                    [
                        'expectedDigestAlg' => $expectedAlg->value,
                        'digestInSignatureAlg' => $signatureAlg->value,
                        'expectedDigest' => $expectedDigest,
                        'digestInSignature' => $digestInSignature,
                    ],
                );
            }
        }

        return new ValidationResult(true);
    }
}
