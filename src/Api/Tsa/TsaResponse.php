<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Tsa;

use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Exceptions\TsaException;

class TsaResponse
{
    public const RESPONSE = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'status' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'status' => [
                        'type' => ASN1::TYPE_INTEGER,
                        'mapping' => [
                            0 => 'granted',
                            1 => 'grantedWithMods',
                            2 => 'rejection',
                            3 => 'waiting',
                            4 => 'revocationWarning',
                            5 => 'revocationNotification',
                        ],
                    ],
                    'statusString' => [
                        'optional' => true,
                        'type' => ASN1::TYPE_SEQUENCE,
                        'min' => 0,
                        'max' => -1,
                        'children' => [
                            'type' => ASN1::TYPE_UTF8_STRING
                        ]
                    ],
                    'failInfo' => [
                        'optional' => true,
                        'type' => ASN1::TYPE_BIT_STRING,
                        'mapping' => [
                            0 => 'badAlg',
                            2 => 'badRequest',
                            5 => 'badDataFormat',
                            14 => 'timeNotAvailable',
                            15 => 'unacceptedPolicy',
                            16 => 'unacceptedExtension',
                            17 => 'addInfoNotAvailable',
                            25 => 'systemFailure'
                        ]
                    ]
                ]
            ],
            'timeStampToken' => [
                'optional' => true,
                'type' => ASN1::TYPE_ANY // No need to map it here
            ]
        ]
    ];

    private array $response;

    public function __construct(string $derData, BigInteger $nonce)
    {
        $this->response = Asn1Helper::decode($derData, self::RESPONSE);

        // Nonce validation
        $nonceInTst = $this->getTimestampTokenObject()->getTimestampInfo()->getNonce();
        if ($nonce->compare($nonceInTst) !== 0) {
            throw new TsaException('Nonce from request does not match nonce in response.');
        }
    }

    /**
     * @return string base64 encoded (used in XAdES document)
     */
    public function getTimestampToken()
    {
        return base64_encode($this->response['timeStampToken']->element);
    }

    public function getTimestampTokenObject(): TimestampToken
    {
        return new TimestampToken($this->response['timeStampToken']->element);
    }
}
