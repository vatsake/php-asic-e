<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Tsa;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\Math\BigInteger;
use Vatsake\AsicE\Api\HttpRequest;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Crypto\DigestAlg;

class TsaRequest implements HttpRequest
{
    private const TSQ_REQUEST = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => ['type' => ASN1::TYPE_INTEGER],
            'messageImprint' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'hashAlgorithm' => AlgorithmIdentifier::MAP,
                    'hashedMessage' => ['type' => ASN1::TYPE_OCTET_STRING],
                ]
            ],
            'reqPolicy' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER, 'optional' => true],
            'nonce' => ['type' => ASN1::TYPE_INTEGER, 'optional' => true],
            'certReq' => ['type' => ASN1::TYPE_BOOLEAN],
            'extensions' => [
                ...Extensions::MAP,
                'implicit' => true,
                'optional' => true,
                'constant' => 0,
            ]
        ]
    ];

    private BigInteger $nonce;

    public function __construct(private string $url, private string $signatureValueXml, private DigestAlg $digest = DigestAlg::SHA256)
    {
        $this->nonce = new BigInteger(random_bytes(16), 256);
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getBody(): string
    {

        $hashedMessage = hash($this->digest->value, $this->signatureValueXml, true);

        $req = [
            'version' => 1,
            'messageImprint' => [
                'hashAlgorithm' => [
                    'algorithm' => $this->digest->getOid()
                ],
                'hashedMessage' => $hashedMessage,
            ],
            'nonce' => $this->getNonce(),
            'certReq' => true,
        ];

        return Asn1Helper::encode($req, self::TSQ_REQUEST);
    }

    public function getNonce(): BigInteger
    {
        return $this->nonce;
    }
}
