<?php

declare(strict_types=1);

namespace Vatsake\AsicE\ASN1;

use phpseclib3\File\ASN1;

abstract class OcspResponse
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'responseStatus' => [
                'type' => ASN1::TYPE_ENUMERATED,
                'mapping' => [
                    0 => 'successful',
                    1 => 'malformedRequest',
                    2 => 'internalError',
                    3 => 'tryLater',
                    5 => 'sigRequired',
                    6 => 'unauthorized',
                ],
            ],
            'responseBytes' => [
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'responseType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                    'response'     => ['type' => ASN1::TYPE_OCTET_STRING],
                ],
            ],

        ]
    ];
}
