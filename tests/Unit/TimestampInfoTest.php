<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Api\Tsa\TimestampInfo;
use Vatsake\AsicE\ASN1\TSTInfo;
use Vatsake\AsicE\Common\Asn1Helper;
use Vatsake\AsicE\Crypto\DigestAlg;

class TimestampInfoTest extends TestCase
{
    private function buildTstInfoDer(string $hashOid, string $hashedMessage, string $genTimeRfc3339): string
    {
        $genTimeGeneralized = gmdate('YmdHis\Z', strtotime($genTimeRfc3339));

        $tst = [
            'version' => 1,
            'policy'  => '1.2.3.4.5.6.7.8',
            'messageImprint' => [
                'hashAlgorithm' => [
                    'algorithm' => $hashOid,
                ],
                'hashedMessage' => $hashedMessage,
            ],
            'serialNumber' => 1,
            'genTime'      => $genTimeGeneralized,
        ];
        return Asn1Helper::encode($tst, TSTInfo::MAP);
    }

    public function testDecodeTstInfoRoundtrip(): void
    {
        $hashOid = DigestAlg::SHA256->getOid();
        $msg = random_bytes(32);
        $when = '2025-10-06T09:00:00Z';

        $der = $this->buildTstInfoDer($hashOid, $msg, $when);
        $info = new TimestampInfo($der);

        $this->assertSame(DigestAlg::SHA256, $info->getHashedAlgorithm());
        $this->assertSame($msg, $info->getHashedMessage());

        $gen = $info->getGenerationTime();
        $this->assertInstanceOf(DateTimeImmutable::class, $gen);
        $this->assertSame(gmdate(DateTimeImmutable::RFC2822, strtotime($when)), $gen->format(DateTimeImmutable::RFC2822));
    }
}
