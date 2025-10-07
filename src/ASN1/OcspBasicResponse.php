<?php

declare(strict_types=1);

namespace Vatsake\AsicE\ASN1;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\CRLReason;
use phpseclib3\File\ASN1\Maps\HashAlgorithm;
use phpseclib3\File\ASN1\Maps\Name;

abstract class OcspBasicResponse
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'tbsResponseData' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'version' => [
                        'type' => ASN1::TYPE_INTEGER,
                        'explicit' => true,
                        'optional' => true,
                        'constant' => 0
                    ],
                    'responderID' => [
                        'type' => ASN1::TYPE_CHOICE,
                        'children' => [
                            'byName' => [
                                ...Name::MAP,
                                'explicit' => true,
                                'constant' => 1,
                            ],
                            'byKey' => [
                                'type' => ASN1::TYPE_OCTET_STRING,
                                'implicit' => true,
                                'constant' => 2,
                            ],
                        ]
                    ],
                    'producedAt' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
                    'responses' => [
                        'type' => ASN1::TYPE_SEQUENCE,
                        'min' => 1,
                        'max' => -1,
                        'children' => [
                            'type' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'certID' => [
                                    'type' => ASN1::TYPE_SEQUENCE,
                                    'children' => [
                                        'hashAlgorithm' => HashAlgorithm::MAP,
                                        'issuerNameHash' => ['type' => ASN1::TYPE_OCTET_STRING],
                                        'issuerKeyHash' => ['type' => ASN1::TYPE_OCTET_STRING],
                                        'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
                                    ]
                                ],
                                'certStatus' => [
                                    'type' => ASN1::TYPE_CHOICE,
                                    'children' => [
                                        'good' => [
                                            'type' => ASN1::TYPE_NULL,
                                            'implicit' => true,
                                            'constant' => 0,
                                        ],
                                        'revoked' => [
                                            'type' => ASN1::TYPE_SEQUENCE,
                                            'implicit' => true,
                                            'constant' => 1,
                                            'children' => [
                                                'revocationTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
                                                'revocationReason' => [
                                                    ...CRLReason::MAP,
                                                    'optional' => true,
                                                    'explicit' => true,
                                                    'constant' => 0,
                                                ],
                                            ]
                                        ],
                                        'unknown' => [
                                            'implicit' => true,
                                            'constant' => 2,
                                            'type' => ASN1::TYPE_NULL
                                        ]
                                    ]
                                ],
                                'thisUpdate' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
                                'nextUpdate' => [
                                    'type' => ASN1::TYPE_GENERALIZED_TIME,
                                    'explicit' => true,
                                    'optional' => true,
                                    'constant' => 0,
                                ],
                                'singleExtensions' => [
                                    ...Sequences::MAP,
                                    'optional' => true,
                                    'explicit' => true,
                                    'constant' => 1
                                ]
                            ]
                        ],
                    ],
                    'responseExtensions' => [
                        ...Sequences::MAP,
                        'optional' => true,
                        'explicit' => true,
                        'constant' => 1
                    ]
                ]
            ],
            'signatureAlgorithm' => HashAlgorithm::MAP,
            'signature' => ['type' => ASN1::TYPE_BIT_STRING],
            'certs' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 1,
                'max' => -1,
                'explicit' => true,
                'optional' => true,
                'constant' => 0,
                'children' => ['type' => ASN1::TYPE_ANY] // No need to map it
            ]
        ]
    ];
}
