<?php

declare(strict_types=1);

namespace Vatsake\AsicE\ASN1;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\File\ASN1\Maps\GeneralName;

abstract class TSTInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => ['type' => ASN1::TYPE_INTEGER],
            'policy'  => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'messageImprint' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'hashAlgorithm' => AlgorithmIdentifier::MAP,
                    'hashedMessage' => ['type' => ASN1::TYPE_OCTET_STRING]
                ]
            ],
            'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
            'genTime'      => ['type' => ASN1::TYPE_GENERALIZED_TIME],

            'accuracy' => [
                'optional' => true,
                'type' => ASN1::TYPE_ANY
            ],
            'ordering' => ['type' => ASN1::TYPE_BOOLEAN, 'default' => false, 'optional' => true],
            'nonce' => [
                'optional' => true,
                'type' => ASN1::TYPE_INTEGER
            ],
            'tsa' => [
                'type' => GeneralName::MAP,
                'explicit' => true,
                'constant' => 0,
                'optional' => true,
            ],
            'extensions' => [
                ...Extensions::MAP,
                'implicit' => true,
                'constant' => 1,
                'optional' => true,
            ],
        ]
    ];
}
