<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Tsa;

use DateTimeImmutable;
use Vatsake\AsicE\ASN1\TSTInfo;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Crypto\DigestAlg;

class TimestampInfo
{
    private array $data;

    public function __construct(string $derData)
    {
        $this->data = Asn1Helper::decode($derData, TSTInfo::MAP);
    }

    public function getHashedAlgorithm(): DigestAlg
    {
        return DigestAlg::fromOid($this->data['messageImprint']['hashAlgorithm']['algorithm']);
    }

    public function getHashedMessage(): string
    {
        return $this->data['messageImprint']['hashedMessage'];
    }

    public function getGenerationTime(): DateTimeImmutable
    {
        return DateTimeImmutable::createFromFormat(DateTimeImmutable::RFC2822, $this->data['genTime']);
    }

    public function getNonce()
    {
        return $this->data['nonce'];
    }
}
