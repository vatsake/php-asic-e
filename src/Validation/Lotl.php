<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation;

use phpseclib3\File\X509;
use Vatsake\AsicE\Api\HttpClient;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Container;
use Vatsake\AsicE\Exceptions\HttpException;

/**
 * Manage the EU LOTL and build a trusted CA store.
 *
 * - Download and parse LOTL/TSL to extract CA X.509 certificates.
 * - Maintain a phpseclib X509 CA store and sha256(DER) fingerprints.
 * - Persist the trusted CA list via AsiceConfig and provide verify()/refresh().
 *
 */
final class Lotl extends Container
{
    private const LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

    /**
     * @var string[] PEM-encoded CA certs; sadly X509 doesn't expose method to list loaded CAs
     * Moved to AsiceConfig - see getLotl()/setLotl() there
     */
    //private array $trustedList = [];
    private null|string $lastLotlLoaded = null;

    /** @var string[] sha256(DER) fingerprints of the loaded CAs */
    private array $fingerprints = [];

    private X509 $trustedListX509;

    /** In-process flag to prevent loads in the same worker */
    private bool $loadingInProgress = false;

    private HttpClient $httpClient;

    protected function __construct()
    {
        $this->trustedListX509 = new X509();
        $this->httpClient = new HttpClient();
    }

    public static function verify(string $certificate): bool
    {
        $instance = self::getInstance();
        $instance->waitUntilLoaded();

        $instance->loadLotlFromConfig();

        if (sizeof($instance->fingerprints) === 0) {
            $instance->refresh();
        }

        // Certificate is a trusted CA
        if (in_array($instance->getCertFingerprint($certificate), $instance->fingerprints, true)) {
            return true;
        }

        $instance->trustedListX509->loadX509($certificate);
        return !!$instance->trustedListX509->validateSignature();
    }

    public static function refresh(): self
    {
        $instance = self::getInstance();
        $instance->loadingInProgress = true;

        $tslUrls = $instance->loadLotl();

        $instance->trustedListX509 = new X509();
        $instance->fingerprints = [];
        $trustedList = [];
        foreach ($tslUrls as $url) {
            $tsls = $instance->loadTsl($url);
            foreach ($tsls as $ca) {
                $trustedList[] = $ca;
                $instance->trustedListX509->loadCA($ca);
                $instance->fingerprints[] = $instance->getCertFingerprint($ca);
            }
        }

        $instance->config()->setLotl($trustedList);
        $instance->lastLotlLoaded = md5(json_encode($trustedList));

        $instance->loadingInProgress = false;
        return $instance;
    }

    private function getCertFingerprint(string $cert): string
    {
        return hash('sha256', base64_decode(Utils::removePemFormatting($cert), true));
    }

    private function loadTsl(string $countryTslUrl): array
    {
        try {
            $tslContents = $this->httpClient->get($countryTslUrl);
        } catch (HttpException $e) {
            return [];
        }
        if ($tslContents === "") {
            return [];
            //throw new \RuntimeException("Failed to download from {$countryTslUrl}.");
        }

        try {
            $xml = new \SimpleXMLElement($tslContents, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        } catch (\Exception $e) {
            return [];
        }

        foreach ($xml->getDocNamespaces(true) as $prefix => $namespace) {
            $xml->registerXPathNamespace($prefix ?: 'd', $namespace);
        }

        $xpath = $xml->xpath('//d:TrustServiceProviderList//d:X509Certificate');

        $certs = [];
        foreach ($xpath as $cert) {
            $certs[] = (string) $cert;
        }

        return $certs;
    }

    private function loadLotl(): array
    {
        $lotlXml = $this->httpClient->get(self::LOTL_URL);
        if ($lotlXml === false) {
            throw new \RuntimeException('Failed to download EU LOTL.');
        }
        $xml = new \SimpleXMLElement($lotlXml, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);

        foreach ($xml->getDocNamespaces() as $prefix => $namespace) {
            $xml->registerXPathNamespace($prefix ?: 'd', $namespace);
        }

        $countryFilter = '';
        if ($this->config()->getCountryCode()) {
            $countryFilter = sprintf(
                '[.//d:SchemeTerritory[text() = "%s"]]',
                strtoupper($this->config()->getCountryCode())
            );
        }

        $xpath = '//d:OtherTSLPointer' .
            '[.//ns3:MimeType[text() = "application/vnd.etsi.tsl+xml"]]' .
            $countryFilter .
            '//d:TSLLocation';

        $locations  = $xml->xpath($xpath);
        if (empty($locations)) {
            throw new \RuntimeException('No TSL location found in LOTL.');
        }

        $urls = [];
        foreach ($locations as $location) {
            if ((string) $location === self::LOTL_URL) {
                continue;
            }
            $urls[] = (string) $location;
        }

        return $urls;
    }

    private function loadLotlFromConfig()
    {
        $lotl = $this->config()->getLotl();

        // Use a hash or strict comparison to detect changes
        $lotlHash = md5(json_encode($lotl));
        if ($this->lastLotlLoaded === $lotlHash) {
            return;
        }

        $this->loadingInProgress = true;
        $this->trustedListX509 = new X509();
        $this->fingerprints = [];
        foreach ($lotl as $ca) {
            $this->trustedListX509->loadCA($ca);
            $this->fingerprints[] = $this->getCertFingerprint($ca);
        }
        $this->lastLotlLoaded = $lotlHash;
        $this->loadingInProgress = false;
    }

    private function config(): AsiceConfig
    {
        return AsiceConfig::getInstance();
    }

    private function waitUntilLoaded(): void
    {
        while ($this->loadingInProgress) {
            usleep(100_000);
        }
    }
}
