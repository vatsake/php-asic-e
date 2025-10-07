<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Ocsp;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\ASN1\Maps\CertificateSerialNumber;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\File\ASN1\Maps\GeneralName;
use phpseclib3\File\X509;
use Vatsake\AsicE\Api\HttpRequest;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Exceptions\InvalidCertificateException;

class OcspRequest implements HttpRequest
{
    private const OCSP_REQUEST_MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'tbsRequest' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'version' => [
                        'type' => ASN1::TYPE_INTEGER,
                        'explicit' => true,
                        'constant' => 0,
                    ],
                    'requestorName' => [
                        ...GeneralName::MAP,
                        'explicit' => true,
                        'optional' => true,
                        'constant' => 1,
                    ],
                    'requestList' => [
                        'type' => ASN1::TYPE_SEQUENCE,
                        'min' => 1,
                        'max' => -1,
                        'children' => [
                            'type' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'reqCert' => [
                                    'type' => ASN1::TYPE_SEQUENCE,
                                    'children' => [
                                        'hashAlgorithm' => AlgorithmIdentifier::MAP,
                                        'issuerNameHash' => ['type' => ASN1::TYPE_OCTET_STRING],
                                        'issuerKeyHash' => ['type' => ASN1::TYPE_OCTET_STRING],
                                        'serialNumber' => CertificateSerialNumber::MAP
                                    ]
                                ],
                                'singleRequestExtensions' => [
                                    ...Extensions::MAP,
                                    'constant' => 0,
                                    'explicit' => true,
                                    'optional' => true,
                                ]
                            ]
                        ]
                    ],
                    'requestExtensions' => [
                        ...Extensions::MAP,
                        'explicit' => true,
                        'optional' => true,
                        'constant' => 2,
                    ]
                ]
            ],
            'optionalSignature' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'signatureAlgorithm' => AlgorithmIdentifier::MAP,
                    'signature' => ['type' => ASN1::TYPE_BIT_STRING],
                    'certs' => [
                        'type' => ASN1::TYPE_SEQUENCE,
                        'explicit' => true,
                        'constant' => 0,
                        'optional' => true,
                        'min' => 1,
                        'max' => -1,
                        'children' => Certificate::MAP
                    ]
                ],
                'explicit' => true,
                'optional' => true,
                'constant' => 0,
            ],
        ]
    ];

    private array $signer;

    private X509 $issuer;

    public function __construct(private string $url, string $signerCertificate, string $issuerCertificate, private DigestAlg $digest = DigestAlg::SHA1)
    {
        $parsedCert = openssl_x509_parse($signerCertificate);
        if ($parsedCert === false) {
            throw new InvalidCertificateException('Invalid signer certificate');
        }
        $this->signer = $parsedCert;

        $parsedCert = openssl_x509_parse($issuerCertificate);
        if ($parsedCert === false) {
            throw new InvalidCertificateException('Invalid issuer certificate');
        }
        $this->issuer = new X509();
        $this->issuer->loadX509($issuerCertificate);
    }

    public function getBody(): string
    {
        $signerSn = Utils::serialToNumber($this->signer['serialNumber']);
        $issuerName = $this->issuer->getDN(X509::DN_ASN1);
        $issuerPubKey = $this->getIssuerPublicKey();

        $req = [
            'tbsRequest' => [
                'version' => 0,
                'requestList' => [
                    [
                        'reqCert' => [
                            'hashAlgorithm' => [
                                'algorithm' => $this->digest->getOid(),
                                'parameters' => null
                            ],
                            'issuerNameHash' => hash($this->digest->value, $issuerName, true),
                            'issuerKeyHash' => hash($this->digest->value, $issuerPubKey, true),
                            'serialNumber' => $signerSn
                        ]
                    ]
                ]
            ]
        ];

        return Asn1Helper::encode($req, self::OCSP_REQUEST_MAP);
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    private function getIssuerPublicKey(): string
    {
        $publicKey = $this->issuer->getPublicKey()->toString('PKCS8');
        $keyData = Utils::stripPubHeaders($publicKey);

        $nodes = ASN1::decodeBER(base64_decode($keyData));

        $key = $nodes[0]['content'][1]['content'];

        // TAG is not hashed
        $key = substr($key, 1);

        return $key;
    }
}
