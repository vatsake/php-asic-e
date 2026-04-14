<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container\Signature;

use Psr\Log\LoggerInterface;
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

    private array $productionPlace = [
        'city' => null,
        'stateOrProvince' => null,
        'postalCode' => null,
        'countryName' => null,
    ];

    private array $signerRoles = [];

    private DigestAlg $signedPropertiesDigestAlg = DigestAlg::SHA256;

    private SignAlg $signatureAlg = SignAlg::ECDSA_SHA256;

    private ?SignatureXml $xmlWriter = null;
    private ?LoggerInterface $logger = null;

    /**
     * @param array<string, array{0: DigestAlg, 1: string}> $fileDigests
     */
    public function __construct(private array $fileDigests)
    {
        $this->logger = AsiceConfig::getLogger();
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
        $this->signerCertificate = Utils::formatAsPemCertificate($certificate);
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

    /**
     * @param array<int, string> $roles
     */
    public function setSignerRoles(array $roles): self
    {
        $this->signerRoles = $roles;
        return $this;
    }

    public function getSignerRoles(): array
    {
        return $this->signerRoles;
    }

    public function setSignatureProductionPlace(null|string $city, null|string $stateOrProvince, null|int|string $postalCode, null|string $countryName): self
    {
        $this->productionPlace = [
            'City' => $city,
            'StateOrProvince' => $stateOrProvince,
            'PostalCode' => $postalCode,
            'CountryName' => $countryName
        ];
        return $this;
    }

    /**
     * @return array{City: string|null, StateOrProvince: string|null, PostalCode: int|string|null, CountryName: string|null}
     */
    public function getSignatureProductionPlace(): array
    {
        return $this->productionPlace;
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
        $startedAt = microtime(true);
        $this->logger?->info('signature_builder.get_data_to_be_signed.start', [
            'fileDigestCount' => count($this->fileDigests),
            'signatureAlg' => $this->signatureAlg->getDigestName(),
            'signedPropertiesDigestAlg' => $this->signedPropertiesDigestAlg->value,
            'raw' => $raw,
        ]);

        if (empty($this->signerCertificate)) {
            $this->logger?->warning('signature_builder.get_data_to_be_signed.signer_not_set');
            throw new \RuntimeException('Cannot get data to be signed: signer certificate not set');
        }

        $this->xmlWriter->createSignedProperties($this->signerCertificate, sizeof($this->fileDigests), $this->productionPlace, $this->signerRoles);
        $this->xmlWriter->createSignedInfo($this->fileDigests, $this->signatureAlg, $this->signedPropertiesDigestAlg);

        $xml = $this->xmlWriter->getSignedInfoCanonicalized();
        if ($raw) {
            $this->logger?->info('signature_builder.get_data_to_be_signed.completed', [
                'raw' => true,
                'outputLength' => strlen($xml),
                'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
            ]);
            return $xml;
        }

        $output = base64_encode(hash($this->signatureAlg->getDigestName(), $xml, true));
        $this->logger?->info('signature_builder.get_data_to_be_signed.completed', [
            'raw' => false,
            'outputLength' => strlen($output),
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return $output;
    }

    /**
     *
     * @param string $signatureValue
     */
    public function finalize(string $signatureValue): FinalizedSignature
    {
        $startedAt = microtime(true);
        $this->logger?->info('signature_builder.finalize.start', [
            'signatureValueLength' => strlen($signatureValue),
        ]);

        $this->xmlWriter->createSignatureAndSignerValues($signatureValue, $this->signerCertificate);

        $signatureValueXml = $this->xmlWriter->getSignatureValueCanonicalized();
        $timestampToken = $this->generateTimestampToken($signatureValueXml);

        $issuerCertificate = Utils::getIssuerCert($this->signerCertificate);
        $ocspToken = $this->generateOcspToken($this->signerCertificate, $issuerCertificate);

        $this->xmlWriter->createUnsignedProperties(Utils::removePemFormatting($issuerCertificate), $timestampToken, $ocspToken);

        $this->logger?->info('signature_builder.finalize.completed', [
            'timestampTokenLength' => strlen($timestampToken),
            'ocspTokenLength' => strlen($ocspToken),
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return new FinalizedSignature($this->xmlWriter, $this->fileDigests);
    }

    private function generateTimestampToken(string $signatureValueNodeCanonicalized): string
    {
        $startedAt = microtime(true);
        $url = AsiceConfig::getTsaUrl();
        if (!$url) {
            $this->logger?->warning('signature_builder.generate_timestamp_token.tsa_url_not_configured');
            throw new ConfigParameterNotSet('TSA URL not configured');
        }

        $this->logger?->debug('signature_builder.generate_timestamp_token.start', [
            'tsaHost' => parse_url($url, PHP_URL_HOST) ?: null,
        ]);

        $request = new TsaRequest($url, $signatureValueNodeCanonicalized);
        $token = (new TsaClient())->sendRequest($request)->getTimestampToken();

        $this->logger?->debug('signature_builder.generate_timestamp_token.completed', [
            'tokenLength' => strlen($token),
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

        return $token;
    }

    private function generateOcspToken(string $signerCert, string $issuerCert): string
    {
        $startedAt = microtime(true);
        $ocspFromConfig = AsiceConfig::getOcspUrl();
        if ($ocspFromConfig) {
            $url = $ocspFromConfig;
            $urlSource = 'config';
        } else {
            $url = Utils::getOcspUrlFromCert($signerCert);
            $urlSource = 'certificate';
        }

        $this->logger?->debug('signature_builder.generate_ocsp_token.start', [
            'urlSource' => $urlSource,
            'ocspHost' => parse_url($url, PHP_URL_HOST) ?: null,
        ]);

        $request = new OcspRequest($url, $signerCert, $issuerCert);
        $token = (new OcspClient())->sendRequest($request)->getToken();

        $this->logger?->debug('signature_builder.generate_ocsp_token.completed', [
            'tokenLength' => strlen($token),
            'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
        ]);

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
