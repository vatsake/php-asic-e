<?php

declare(strict_types=1);

namespace Vatsake\AsicE\ASN1;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Attribute;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\ASN1\Maps\CertificateList;
use phpseclib3\File\ASN1\Maps\CertificateSerialNumber;
use phpseclib3\File\ASN1\Maps\GeneralNames;
use phpseclib3\File\ASN1\Maps\Name;
use phpseclib3\File\ASN1\Maps\UniqueIdentifier;

abstract class TimestampToken
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'contentType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'content' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'constant' => 0,
                'explicit' => true,
                'children' => [
                    'version' => ['type' => ASN1::TYPE_INTEGER],
                    'digestAlgorithms' => [
                        'type' => ASN1::TYPE_SET,
                        'min' => 1,
                        'max' => -1,
                        'children' => AlgorithmIdentifier::MAP,
                    ],
                    'encapContentInfo' => [
                        'type' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            'eContentType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                            'eContent' => ['type' => ASN1::TYPE_OCTET_STRING, 'constant' => 0, 'optional' => true, 'explicit' => true]
                        ]
                    ],
                    'certificates' => [
                        'type' => ASN1::TYPE_SET,
                        'implicit' => true,
                        'min' => 1,
                        'max' => -1,
                        'constant' => 0,
                        'optional' => true,
                        'children' => [
                            'type' => ASN1::TYPE_CHOICE,
                            'children' => [
                                'certificate' => Certificate::MAP, // This is the most common, for some reason ANY type gives error
                                'extendedCertificate' => ['type' => ASN1::TYPE_ANY, 'implicit' => true, 'constant' => 0],
                                'attrCert' => [
                                    'type' => ASN1::TYPE_SEQUENCE,
                                    'implicit' => true,
                                    'constant' => 1,
                                    'children' => [
                                        'acinfo' => [
                                            'type' => ASN1::TYPE_SEQUENCE,
                                            'children' => [
                                                'version' => ['type' => ASN1::TYPE_INTEGER],
                                                'holder' => [
                                                    'type' => ASN1::TYPE_SEQUENCE,
                                                    'children' => [
                                                        'baseCertificateId' => [
                                                            'type' => ASN1::TYPE_SEQUENCE,
                                                            'optional' => true,
                                                            'constant' => 0,
                                                            'children' => [
                                                                'issuer' => GeneralNames::MAP,
                                                                'serial' => CertificateSerialNumber::MAP,
                                                                'issuerUID' => [...UniqueIdentifier::MAP, 'optional' => true]
                                                            ]
                                                        ],
                                                        'entitiyName' => [
                                                            'type' => GeneralNames::MAP,
                                                            'constant' => 1,
                                                            'optional' => true
                                                        ],
                                                        'objectDigestInfo' => [
                                                            'type' => ASN1::TYPE_SEQUENCE,
                                                            'optional' => true,
                                                            'constant' => 2,
                                                            'children' => [
                                                                'digestedObjectType' => [
                                                                    'type' => ASN1::TYPE_ENUMERATED,
                                                                    'mapping' => [
                                                                        0 => 'publicKey',
                                                                        1 => 'publicKeyCert',
                                                                        2 => 'otherObjectTypes',
                                                                    ],
                                                                ],
                                                                'otherObjectTypeID' => [
                                                                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                                                                    'optional' => true,
                                                                ],
                                                                'digestAlgorithm' => AlgorithmIdentifier::MAP,
                                                                'objectdigest' => ['type' => ASN1::TYPE_BIT_STRING]
                                                            ]
                                                        ]
                                                    ]
                                                ],
                                            ],
                                        ],
                                        'signatureAlgorithm' => AlgorithmIdentifier::MAP,
                                        'signatureValue' => ['type' => ASN1::TYPE_BIT_STRING],
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'crls' => [
                        'type' => ASN1::TYPE_SET,
                        'implicit' => true,
                        'optional' => true,
                        'constant' => 1,
                        'min' => 1,
                        'max' => -1,
                        'children' => [
                            'type' => ASN1::TYPE_SEQUENCE,
                            'children' => CertificateList::MAP
                        ]
                    ],
                    'signerInfos' => [
                        'type' => ASN1::TYPE_SET,
                        'min' => 1,
                        'max' => -1,
                        'children' => [
                            'type' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'version' => ['type' => ASN1::TYPE_INTEGER],
                                'sid' => [
                                    'type' => ASN1::TYPE_CHOICE,
                                    'children' => [
                                        'issuerAndSerialNumber' => [
                                            'type' => ASN1::TYPE_SEQUENCE,
                                            'children' => [
                                                'issuer' => Name::MAP,
                                                'serialNumber' => CertificateSerialNumber::MAP,
                                            ]
                                        ],
                                        'subjectKeyIdentifier' => [
                                            'constant' => 0,
                                            'type' => ASN1::TYPE_OCTET_STRING,
                                        ]
                                    ]
                                ],
                                'digestAlgorithm' => AlgorithmIdentifier::MAP,
                                'signedAttrs' => [
                                    'type' => ASN1::TYPE_SET,
                                    'min' => 1,
                                    'max' => -1,
                                    'implicit' => true,
                                    'constant' => 0,
                                    'optional' => true,
                                    'children' => Attribute::MAP,
                                ],
                                'signatureAlgorithm' => AlgorithmIdentifier::MAP,
                                'signature' => ['type' => ASN1::TYPE_OCTET_STRING],
                                'unsignedAttrs' => [
                                    'type' => ASN1::TYPE_SET,
                                    'min' => 1,
                                    'max' => -1,
                                    'implicit' => true,
                                    'constant' => 1,
                                    'optional' => true,
                                    'children' => Attribute::MAP,
                                ]
                            ]
                        ]
                    ]
                ]

            ]
        ]
    ];
}
