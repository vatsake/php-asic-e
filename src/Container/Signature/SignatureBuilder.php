<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container\Signature;

use Vatsake\AsicE\Api\Ocsp\OcspClient;
use Vatsake\AsicE\Api\Ocsp\OcspRequest;
use Vatsake\AsicE\Api\Tsa\TsaClient;
use Vatsake\AsicE\Api\Tsa\TsaRequest;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Crypto\SignAlg;
use Vatsake\AsicE\Exceptions\ConfigParameterNotSet;

final class SignatureBuilder
{
    private ?string $signerCertificate;

    private DigestAlg $signedPropertiesDigestAlg = DigestAlg::SHA256;

    private SignAlg $signatureAlg = SignAlg::ECDSA_SHA256;

    private ?SignatureXml $xmlWriter = null;

    /**
     * @param array<string, array{0: DigestAlg, 1: string}> $fileDigests
     */
    public function __construct(private array $fileDigests)
    {
        $this->xmlWriter = new SignatureXml();
    }

    public function toXml()
    {
        return $this->xmlWriter->toXml();
    }

    /**
     * @param string $certificate In base64 format
     */
    public function setSigner(string $certificate): self
    {
        $this->signerCertificate = $certificate;
        return $this;
    }

    /**
     * Get the signer certificate in base64 format
     */
    public function getSigner(): ?string
    {
        return $this->signerCertificate;
    }

    public function setSignatureAlg(SignAlg $signAlg): self
    {
        $this->signatureAlg = $signAlg;
        return $this;
    }

    public function getSignatureAlg(): SignAlg
    {
        return $this->signatureAlg;
    }

    public function setSignedPropertiesDigestAlg(DigestAlg $digestAlg): self
    {
        $this->signedPropertiesDigestAlg = $digestAlg;
        return $this;
    }

    /**
     * This function creates signed properties and signed info elements of XAdES
     *
     * To change signing algorithm, use setSignatureAlg method; Default ecdsa-sha256
     * @param bool $raw if true, return raw data instead of base64 encoded hash
     * @return string data to be signed with a private key
     */
    public function getDataToBeSigned(bool $raw = false): string
    {
        if (empty($this->signerCertificate)) {
            throw new \RuntimeException('Cannot get data to be signed: signer certificate not set');
        }

        $this->xmlWriter->createSignedProperties($this->signerCertificate, sizeof($this->fileDigests));
        $this->xmlWriter->createSignedInfo($this->fileDigests, $this->signatureAlg, $this->signedPropertiesDigestAlg);

        $xml = $this->xmlWriter->getSignedInfoCanonicalized();
        if ($raw) {
            return $xml;
        }
        return base64_encode(hash($this->signatureAlg->getDigestName(), $xml, true));
    }

    /**
     *
     * @param string $signatureValue
     */
    public function finalize(string $signatureValue): FinalizedSignature
    {
        $this->xmlWriter->createSignatureAndSignerValues($signatureValue, $this->signerCertificate);

        $signatureValueXml = $this->xmlWriter->getSignatureValueCanonicalized();
        $timestampToken = $this->generateTimestampToken($signatureValueXml);

        $issuerCertificate = Utils::getIssuerCert($this->signerCertificate);
        $ocspToken = $this->generateOcspToken($this->signerCertificate, $issuerCertificate);

        $this->xmlWriter->createUnsignedProperties(Utils::stripPemHeaders($issuerCertificate), $timestampToken, $ocspToken);
        return new FinalizedSignature($this->xmlWriter, $this->fileDigests);
    }

    public function generateTimestampToken(string $signatureValueNodeCanonicalized): string
    {
        $url = AsiceConfig::getTsaUrl();
        if (!$url) {
            throw new ConfigParameterNotSet('TSA URL not configured');
        }

        $request = new TsaRequest($url, $signatureValueNodeCanonicalized);
        $token = (new TsaClient())->sendRequest($request)->getTimestampToken();
        return $token;
    }

    public function generateOcspToken(string $signerCert, string $issuerCert): string
    {
        $url = AsiceConfig::getOcspUrl();
        if (!$url) {
            throw new ConfigParameterNotSet('OCSP URL not configured');
        }

        $request = new OcspRequest($url, $signerCert, $issuerCert);
        $token = (new OcspClient())->sendRequest($request)->getToken();
        return $token;
    }

    public function __serialize(): array
    {
        return [
            'sn' => $this->signerCertificate,
            'spdalg' => $this->signedPropertiesDigestAlg->value,
            'signAlg' => $this->signatureAlg->value,
            'fileDigests' => $this->fileDigests,
            'xml' => $this->xmlWriter->toXml()
        ];
    }

    public function __unserialize(array $data)
    {
        $this->signerCertificate = $data['sn'];
        $this->signedPropertiesDigestAlg = DigestAlg::from($data['spdalg']);
        $this->signatureAlg = SignAlg::from($data['signAlg']);
        $this->fileDigests = $data['fileDigests'];
        $this->xmlWriter = new SignatureXml($data['xml']);
    }
}
