<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Common;

use phpseclib3\File\ASN1;
use Vatsake\AsicE\Exceptions\Asn1Exception;

class Asn1Helper
{
    public static function decode(string $data, array $mapping): array
    {
        $decoded = ASN1::decodeBER($data);
        if (!$decoded) {
            throw new Asn1Exception('ASN1 decoding failed');
        }

        $mapped = ASN1::asn1map($decoded[0], $mapping);
        if (!$mapped) {
            throw new Asn1Exception('ASN1 mapping failed with mapping: ' . json_encode($mapping, JSON_PRETTY_PRINT));
        }

        return $mapped;
    }

    public static function encode(array $data, array $mapping): string
    {
        $encodedData = ASN1::encodeDER($data, $mapping);
        if ($encodedData === false) {
            throw new Asn1Exception('ASN1 mapping failed: ' . json_encode($mapping, JSON_PRETTY_PRINT));
        }
        return $encodedData;
    }
}
