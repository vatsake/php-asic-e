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

// Configure TSA (and OCSP) endpoints
// If setting OCSP endpoint here, it will only use that endpoint
AsiceConfig::setOcspUrl(/* OCSP URL */)
    ->setTsaUrl(/* TSA URL */);

// 1a: Create a new ASiC-E container
$uc = new UnsignedContainer();
$uc->addFile('foo.txt', 'bar');
$container = $uc->build(__DIR__ . '/foobar.asice'); // Writes to disk

// 1b: Existing container
$container = Container::open(__DIR__ . '/foobar.asice');

// 2. Prepare a signature
$builder = $container->createSignature();
$dataToBeSigned = $builder
  ->setSigner($signingCert) // PEM certificate
  ->setSignatureAlg(SignAlg::ECDSA_SHA256) // (optional) Signing algorithm (default SHA-256)
  ->setSignatureProductionPlace('Tallinn', 'Harjumaa', 99999, 'EE') // (optional)
  ->setSignerRoles(['Agreed']) // (optional)
  ->getDataToBeSigned(true); // true → raw canonicalized bytes
// Typically $dataToBeSigned (not raw) is returned to the user to sign; so we have to save incomplete signature somewhere (preferably in user's session)
file_put_contents('temp', serialize($builder));


// 3. User signs data
// Typically $dataToBeSigned (not raw) is returned to the user to sign (if signing via ID-card)
// In php it could be something like this:
$pkeyid = openssl_pkey_get_private(/* Private key */);
openssl_sign($dataToBeSigned, $signatureValue, $pkeyid, OPENSSL_ALGO_SHA256); // PHP's openssl sign needs RAW sign data


// 4. Finalize and attach the signature
/** @var \Vatsake\AsicE\Container\Signature\SignatureBuilder */
$signature = unserialize(file_get_contents('temp'));
$finalizedSignature = $signature->finalize($signatureValue);

$container = Container::open(__DIR__ . '/foobar.asice');
$container->addSignature($finalizedSignature);
```

### 🚀 Signing example with Smart-ID client library

Unfortunately the base Smart-id client doesn't support signing, so I forked the base library and added signing support

```bash
composer require vatsake/smart-id-php-client
```

```php
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Container\UnsignedContainer;
use Vatsake\AsicE\Crypto\SignAlg;
use Sk\SmartId\Api\Data\SignableData;
use Sk\SmartId\Api\Data\SemanticsIdentifier;
use Sk\SmartId\Api\Data\Interaction;
use Sk\SmartId\Client;

AsiceConfig::setTsaUrl('http://tsa.demo.sk.ee/tsa');

# Smart ID client
$client = new Client();
$client->setRelyingPartyUUID('00000000-0000-0000-0000-000000000000')
  ->setRelyingPartyName('DEMO')
  ->setHostUrl('https://sid.demo.sk.ee/smart-id-rp/v2/');

# Create container and add file
$uc = new UnsignedContainer();
$uc->addFile('foo.txt', 'bar');
$container = $uc->build(__DIR__ . '/foobar.asice');

# Get the signing certificate
$semanticsIdentifier = SemanticsIdentifier::builder()
  ->withSemanticsIdentifierType('PNO')
  ->withCountryCode('LT')
  ->withIdentifier('30303039914')
  ->build();

try {
  $resp = $client->signature()
    ->createCertificateChoice()
    ->withSemanticsIdentifier($semanticsIdentifier)
    ->chooseCertificate();
} catch (\Exception $e) {
  var_dump($e);
  exit;
  // Check official documentation to catch all exceptions
}

# Get data to be signed
$builder = $container->createSignature();
$dataToBeSigned = $builder
  ->setSigner($resp->getCertificate()) // PEM certificate
  ->setSignatureAlg(SignAlg::RSA_SHA256) // SMART-ID uses RSA algorithm
  ->setSignatureProductionPlace('Tallinn', 'Harjumaa', 99999, 'EE') // (optional)
  ->setSignerRoles(['Agreed']) // (optional)
  ->getDataToBeSigned(true); // RAW - SignableData from Smart-id library gets digest
// Might need to save builder instance
file_put_contents('temp', serialize($builder));

# Sign data via Smart-id

$data = new SignatureHash($dataToBeSigned);
$data->setHashType('SHA256');
echo 'vccode ' . $data->calculateVerificationCode();

try {
  $resp = $client->signature()->createSignature()
      ->withDocumentNumber($resp->getDocumentNumber())
      ->withSignableData($data)
      ->withAllowedInteractionsOrder([
          Interaction::ofTypeVerificationCodeChoice('Sign?')
      ])
      ->sign();
} catch (\Exception $e) { // Use exceptions below
  var_dump($e);
  exit;
  // Check official documentation to catch all exceptions
}

// Attach signature
/** @var \Vatsake\AsicE\Container\Signature\SignatureBuilder */
$signature = unserialize(file_get_contents('temp'));
$finalizedSignature = $signature->finalize($resp->getValueInBase64());
$container = Container::open(__DIR__ . '/foobar.asice');
$container->addSignature($finalizedSignature);
```

### 🚀 Signing example with Mobile-ID client library

Unfortunately the base Mobile-id client doesn't support signing, so I forked the base library and added signing support

```bash
composer require vatsake/mobile-id-php-client
```

```php
use Sk\Mid\DisplayTextFormat;
use Sk\Mid\Language\ENG;
use Sk\Mid\MobileIdClient;
use Sk\Mid\MobileIdSignatureHashToSign;
use Sk\Mid\Rest\Dao\Request\CertificateRequest;
use Sk\Mid\Rest\Dao\Request\SignatureRequest;
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Container\UnsignedContainer;
use Vatsake\AsicE\Crypto\SignAlg;

AsiceConfig::setTsaUrl('http://tsa.demo.sk.ee/tsa');

# Mobile ID client
$client = MobileIdClient::newBuilder()
    ->withRelyingPartyUUID('00000000-0000-0000-0000-000000000000')
    ->withRelyingPartyName('DEMO')
    ->withLongPollingTimeoutSeconds(60)
    ->withHostUrl('https://tsp.demo.sk.ee/mid-api')
    ->build();

# Create container and add file
$uc = new UnsignedContainer();
$uc->addFile('foo.txt', 'bar');
$container = $uc->build(__DIR__ . '/foobar.asice');

# Get the signing certificate
$request = CertificateRequest::newBuilder()
    ->withPhoneNumber('+37200000766')
    ->withNationalIdentityNumber('60001019906')
    ->build();

try {
    $resp = $client->getMobileIdConnector()->pullCertificate($request);
} catch (\Exception $e) {
    var_dump($e);
    exit;
    // Check official documentation to catch all exceptions
}

# Get data to be signed
$builder = $container->createSignature();
$dataToBeSigned = $builder
    ->setSigner($resp->getCert()) // PEM certificate
    ->setSignatureAlg(SignAlg::ECDSA_SHA256) // MOBILE-ID uses ECDSA algorithm
    ->setSignatureProductionPlace('Tallinn', 'Harjumaa', 99999, 'EE') // (optional)
    ->setSignerRoles(['Agreed']) // (optional)
    ->getDataToBeSigned();
// Might need to save builder instance
file_put_contents('temp', serialize($builder));

$hash = MobileIdSignatureHashToSign::newBuilder()->withHashInBase64($dataToBeSigned)->withHashType('sha256')->build();
$verificationCode = $hash->calculateVerificationCode(); // Show this to user

# Sign data via Mobile-id

$request = SignatureRequest::newBuilder()
    ->withPhoneNumber('+37200000766')
    ->withNationalIdentityNumber('60001019906')
    ->withHashToSign($hash)
    ->withLanguage(ENG::asType())
    ->withDisplayText("Sign document?")
    ->withDisplayTextFormat(DisplayTextFormat::GSM7)
    ->build();

try {
    $response = $client->getMobileIdConnector()->initSignature($request);
} catch (\Exception $e) { // Use exceptions below
    var_dump($e);
    exit;
    // Check official documentation to catch all exceptions
}

# Poll until final result
$finalSessionStatus = $client
    ->getSessionStatusPoller()
    ->fetchFinalSignatureSessionStatus($response->getSessionID(), 60);

try {
    $result = $client->createMobileIdSignature($finalSessionStatus, $hash);
} catch (\Exception $e) {
    var_dump($e);
    exit;
    // Check official documentation to catch all exceptions
}

// Attach signature
/** @var \Vatsake\AsicE\Container\Signature\SignatureBuilder */
$signature = unserialize(file_get_contents('temp'));
$finalizedSignature = $signature->finalize($result->getSignatureValueInBase64());
$container = Container::open(__DIR__ . '/foobar.asice');
$container->addSignature($finalizedSignature);
```

## ✅ Validating signatures

```php
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\AsiceConfig;

AsiceConfig::setCountryCode('EE'); // Limit trust anchors to Estonia

$container = Container::open('/foobar.asice');

// Option 1 – validate all signatures
$container->validateSignatures(); // Returns array<array{index: int, valid: bool, errors: ValidationResult[]}>

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

> [!NOTE]
> This library has a limited user base (me, myself and I 😉), so there's bound to be some bugs. Feel free to report issues or contribute improvements!

## ⚖️ License

Released under the **MIT License**.
