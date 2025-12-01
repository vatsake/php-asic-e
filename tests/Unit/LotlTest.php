<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Validation\Lotl;

class LotlTest extends TestCase
{
    private const TEST_CA_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'testCA.crt';
    private const TEST_TRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'signer.crt';
    private const TEST_UNTRUSTED_X509_PATH = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Certs' . DIRECTORY_SEPARATOR . 'untrusted.crt';

    public function setUp(): void
    {
        // Reset config and Lotl singleton for each test
        AsiceConfig::getInstance()->setCountryCode('EE')->setLotl([]);
    }

    public function testGetInstanceReturnsSameInstance()
    {
        $instance1 = Lotl::getInstance();
        $instance2 = Lotl::getInstance();
        $this->assertSame($instance1, $instance2);
    }

    public function testVerifyTrustedCertificate()
    {
        $ca = file_get_contents(self::TEST_CA_PATH);

        $config = AsiceConfig::getInstance();
        $config->setCountryCode('EE')->setLotl([Utils::removePemFormatting($ca)]);

        $signer = file_get_contents(self::TEST_TRUSTED_X509_PATH);
        $this->assertTrue(Lotl::verify($signer));
    }

    public function testVerifytUntrustedCertificate()
    {
        $ca = file_get_contents(self::TEST_CA_PATH);

        $config = AsiceConfig::getInstance();
        $config->setCountryCode('EE')->setLotl([Utils::removePemFormatting($ca)]);

        $signer = file_get_contents(self::TEST_UNTRUSTED_X509_PATH);
        $this->assertFalse(Lotl::verify($signer));
    }

    public function testVerifytCACertificate()
    {
        $ca = file_get_contents(self::TEST_CA_PATH);

        $config = AsiceConfig::getInstance();
        $config->setCountryCode('EE')->setLotl([Utils::removePemFormatting($ca)]);

        $this->assertTrue(Lotl::verify($ca));
    }

    public function testRefreshSpecificCountry()
    {
        $config = AsiceConfig::getInstance();
        $config->setCountryCode('EE');

        Lotl::refresh();

        $this->assertGreaterThan(1, count($config->getLotl()));
        $this->assertLessThan(1000, count($config->getLotl())); // Without a countrycode there's thousands of certs
        $this->assertEquals('EE', $config->getCountryCode());
    }

    public function testVerifyUpdatesTrustedList()
    {
        // Settings country code so it doesn't try to download everything
        $config = AsiceConfig::getInstance();
        $config->setCountryCode('EE')->setLotl([]);

        $signer = file_get_contents(self::TEST_UNTRUSTED_X509_PATH);

        $currentLotl = $config::getLotl();
        $this->assertEquals([], $currentLotl);
        Lotl::verify($signer);

        $newLotl = $config::getLotl();
        $this->assertGreaterThan(1, $newLotl);
    }

    public function testLoadsLotlFromConfig()
    {
        $ca1 = file_get_contents(self::TEST_CA_PATH);
        AsiceConfig::getInstance()->setLotl([Utils::removePemFormatting($ca1)]);

        $lotl = Lotl::getInstance();
        $lotl->verify($ca1);

        // Should have loaded CA
        $this->assertCount(1, $this->getPrivateProperty($lotl, 'fingerprints'));
    }

    public function testDoesNotReloadIfLotlUnchanged()
    {
        $ca1 = file_get_contents(self::TEST_CA_PATH);
        AsiceConfig::getInstance()->setLotl([Utils::removePemFormatting($ca1)]);

        $lotl = Lotl::getInstance();
        $lotl->verify($ca1);
        $firstFingerprints = $this->getPrivateProperty($lotl, 'fingerprints');

        // Call again with same config, should not reload
        $lotl->verify($ca1);
        $secondFingerprints = $this->getPrivateProperty($lotl, 'fingerprints');

        $this->assertSame($firstFingerprints, $secondFingerprints);
    }

    public function testReloadsIfLotlChanges()
    {
        $ca1 = file_get_contents(self::TEST_CA_PATH);
        $trustedCert = file_get_contents(self::TEST_TRUSTED_X509_PATH);
        AsiceConfig::getInstance()->setLotl([Utils::removePemFormatting($ca1)]);

        $lotl = Lotl::getInstance();
        $lotl->verify($ca1);
        $firstFingerprints = $this->getPrivateProperty($lotl, 'fingerprints');

        // Change config
        AsiceConfig::getInstance()->setLotl([Utils::removePemFormatting($trustedCert)]);
        $lotl->verify($ca1);
        $secondFingerprints = $this->getPrivateProperty($lotl, 'fingerprints');

        $this->assertNotSame($firstFingerprints, $secondFingerprints);
    }

    // Helper to access private properties for assertions
    private function getPrivateProperty($object, $property)
    {
        $ref = new \ReflectionProperty($object, $property);
        $ref->setAccessible(true);
        return $ref->getValue($object);
    }
}
