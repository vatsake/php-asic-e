<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Tsa;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Certificate;
use Vatsake\AsicE\Api\Tsa\TimestampInfo;
use Vatsake\AsicE\ASN1\TimestampToken as ASN1TimestampToken;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Crypto\SignAlg;

class TimestampToken
{
    private array $data;

    public function __construct(string $derData)
    {
        $this->data = Asn1Helper::decode($derData, ASN1TimestampToken::MAP);
    }

    public function getTsaResponderCertificate()
    {
        return Utils::formatAsPemCertificate(base64_encode(Asn1Helper::encode($this->data['content']['certificates'][0]['certificate'], Certificate::MAP)));
    }

    public function getSignature()
    {
        // Ignore first byte
        return substr($this->data['content']['signerInfos'][0]['signature'], 1);
    }

    public function getSignatureAlgorithm(): SignAlg
    {
        $alg = ASN1::getOID($this->data['content']['signerInfos'][0]['signatureAlgorithm']['algorithm']);
        return SignAlg::fromOid($alg);
    }

    public function getSignedData(): string
    {
        // Encode signedAttrs back to DER
        return Asn1Helper::encode($this->data['content']['signerInfos'][0]['signedAttrs'], ASN1TimestampToken::MAP['children']['content']['children']['signerInfos']['children']['children']['signedAttrs']);
    }

    public function getTimestampInfo(): TimestampInfo
    {
        return new TimestampInfo($this->data['content']['encapContentInfo']['eContent']);
    }
}
