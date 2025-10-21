# PHP-ASICE

[![Latest Version](https://img.shields.io/packagist/v/vatsake/php-asic-e.svg)](https://packagist.org/packages/vatsake/php-asic-e)
[![License](https://img.shields.io/github/license/vatsake/php-asic-e.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D%208.1-blue.svg)]()

A lightweight PHP library for creating and validating **ASiC-E** (Associated Signature Container – Extended) files with **XAdES-T** digital signatures.

## ✨ Features

- Create **XAdES-T** (timestamped) signatures
- Build and validate **ASiC-E** digital signature containers
- Built-in **OCSP** and **timestamp** support
- Certificate chain and signature validation
- **ASN.1** (powered by phpseclib 3) and **XML** utilities
<blockquote>
The library currently produces XAdES-T signatures (BES + trusted timestamp + OCSP).<br>
Long-term profiles (XAdES-LT / LTA) are not yet implemented.
</blockquote>

## 🧩 Installation

Install via Composer:

```bash
composer require vatsake/php-asic-e
```

## 🚀 Usage

```php
<?php
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Container\UnsignedContainer;
use Vatsake\AsicE\Crypto\SignAlg;

// Configure TSA and OCSP endpoints
AsiceConfig::setOcspUrl(/* OCSP URL */)
  ->setTsaUrl(/* TSA URL */);

// 1a: Create a new ASiC-E container
$uc = new UnsignedContainer();
$uc->addFile('foo.txt', 'bar');
$container = $uc->build(__DIR__ . '\foobar.asice'); // Writes to disk

// 1b: Existing container
$container = new Container(__DIR__ . '\foobar.asice');

// 2. Prepare a signature
$builder = $container->createSignature();
$dataToBeSigned = $builder
  ->setSigner($signingCert) // PEM certificate
  ->setSignatureAlg(SignAlg::ECDSA_SHA256) // (optional) Signing algorithm (default SHA-256)
  ->setSignatureProductionPlace('Tallinn', 'Harjumaa', 99999, 'EE') // (optional)
  ->setSignerRoles(['Agreed']) // (optional)
  ->getDataToBeSigned(true); // true → raw canonicalized bytes
// Typically $dataToBeSigned (not raw) is returned to the user to sign; so we have to save incomplete signature somewhere (preferrably in user's session)
file_put_contents('temp', serialize($signature));


// 3. User signs data
// In php it could be something like this:
$pkeyid = openssl_pkey_get_private(/* Private key */);
openssl_sign($dataToBeSigned, $signatureValue, $pkeyid, OPENSSL_ALGO_SHA256); // PHP's openssl sign needs RAW sign data


// 4. Finalize and attach the signature
/** @var \Vatsake\AsicE\Container\Signature\SignatureBuilder */
$signature = unserialize(file_get_contents('temp'));
$finalizedSignature = $signature->finalize($signatureValue);

$container = new Container(__DIR__ . '\foobar.asice');
$container->addSignature($finalizedSignature);
```

## ✅ Validating signatures

```php
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\AsiceConfig;

AsiceConfig::setCountryCode('EE'); // Limit trust anchors to Estonia

$container = new Container('/foobar.asice');

// Option 1 – validate all signatures
$container->validateSignatures(); // Returns array{index: int, valid: bool, errors: ValidationResult[]}

// Option 2 – iterate manually
foreach ($container->getSignatures() as $i => $sig) {
    $ok = $sig->isValid();
    echo $i . ': ' . ($ok ? 'OK' : 'NOK') . PHP_EOL;
    if (!$ok) var_dump($sig->getValidationErrors());
}
```

## 🔗 Official SK ID Solutions Endpoints & Docs

For full technical information about Estonian OCSP and TSA services, see:

- **Timestamping service:** https://github.com/SK-EID/Timestamping/wiki/Timestamping-Service-Technical-Information
- **OCSP service:** https://github.com/SK-EID/ocsp/wiki

**Default production endpoints (Estonia):**

```
OCSP: http://ocsp.sk.ee
TSA : http://tsa.sk.ee
```

**Default test endpoints (Estonia):**

```
OCSP: http://demo.sk.ee/ocsp
TSA : http://tsa.demo.sk.ee/tsa
```

<blockquote>
These public endpoints are operated by SK ID Solutions AS (Estonia) and are used by ID-card, Mobile-ID and Smart-ID.<br>
Signatures created with them are fully compatible with DigiDoc4.
</blockquote>

## ⚙️ Best practices

Load the **LOTL** (List of Trusted Lists) once on startup and cache it to avoid network delays.<br>
It is recommended to update LOTL every 24h.

```php
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\AsiceConfig;

// Bootstrap
Lotl::refresh(); // This force loads all trust anchors (without country code it's about 4.5k trust anchors)
$lotl = AsiceConfig::getLotl(); // Returns array of trust anchors
file_put_contents('foo', json_encode($lotl)); // Your application might have a cache server

// Later (from cache)
$lotl = json_decode(file_get_contents('foo'), true); // Again, you might have a cache server
AsiceConfig::setLotl($lotl)
  ->setOcspUrl(/* OCSP URL */)
  ->setTsaUrl(/* TSA URL */)
  ->setCountryCode('EE'); // If you filter trust anchors by country
```

<blockquote>
⚠️ Without filtering by country code, the LOTL contains ≈ 4 500 CA certificates,<br>
which can slow initialization and increase memory use.
</blockquote>

## 🧱 Requirements

- PHP 8.1 or higher
- phpseclib 3 (used internally for ASN.1, OCSP, and TSA parsing)
- OpenSSL extension enabled
- DOM and XML extensions

## 🧠 Technical notes

- Implements the **ETSI EN 319 162 / XAdES-T** profile (BES + timestamp + OCSP),
  identical in structure to DigiDoc’s “BES / time-stamp” signatures.
- Uses **phpseclib 3** for:
  - ASN.1 DER decoding
  - OCSP and TSA response parsing
  - Certificate and key handling where OpenSSL alone is insufficient
- Long-term (LT/LTA) and archival timestamping are planned for future versions.
- Fully compatible with **Estonian DigiDoc** — DigiDoc will display these as<br>
  **“BES / time-stamp“ (XAdES-T)** signatures

## ⚖️ License

Released under the **MIT License**.
