<?php

declare(strict_types=1);

namespace Vatsake\AsicE\ASN1;

use phpseclib3\File\ASN1;

abstract class Sequences
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'min' => 1,
        'max' => -1,
        'children' => [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'extnID' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                'critical' => ['type' => ASN1::TYPE_BOOLEAN, 'default' => false],
                'extnValue' => ['type' => ASN1::TYPE_OCTET_STRING],
            ]
        ]
    ];
}
