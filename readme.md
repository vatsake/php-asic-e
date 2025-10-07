# PHP-ASICE

[![Latest Version](https://img.shields.io/packagist/v/vatsake/php-asice.svg)](https://packagist.org/packages/vatsake/php-asice)
[![License](https://img.shields.io/github/license/vatsake/php-asice.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D%208.1-blue.svg)]()

A PHP library for creating and validating XAdES signatures and ASiC-E containers.

## Features

- Create XAdES signatures
- Build and validate ASiC-E digital signature containers
- OCSP and timestamp support
- Certificate and signature validation
- ASN.1 and XML utilities

## Installation

Install via Composer:

```bash
composer require vatsake/php-asic-e
```

## Usage

```php
<?php
use Vatsake\AsicE\AsiceConfig;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Container\UnsignedContainer;

// The signatures have a timestamp and OCSP,
// providing real-time revocation checking and trusted time evidence for long-term validation (LT-level).
AsiceConfig::setOcspUrl(/* OCSP URL */)
  ->setTsaUrl(/* TSA URL */);

// Example: Create a new ASiC-E container
$uc = new UnsignedContainer();
$uc->addFile('foo.txt', 'bar');
$container = $uc->build(getcwd() . '\foobar.asice'); // This writes to disk

// Example: Add a signature to it
$signature = $container->createSignature();
$dataToBeSigned = $signature
  ->setSigner($signingCert) // Signature in base64 format
  ->setSignatureAlg(SignAlg::ECDSA_SHA3_512) // Signing algorithm (default SHA-256)
  ->getDataToBeSigned(); // Returns hash that has to be signed; If you need raw signed data, pass in true parameter
// Typically $dataToBeSigned is returned to the user to sign; so we have to save incomplete signature somewhere (preferrably in user's session)
file_put_contents('temp', serialize($signature));


// User signs data
// In php it could be something like this:
$pkeyid = openssl_pkey_get_private(/* Private key */);
openssl_sign($dataToBeSigned, $signatureValue, $pkeyid, OPENSSL_ALGO_SHA256); // PHP's openssl sign needs RAW sign data


// Add signature value to the signature
/** @var \Vatsake\AsicE\Container\Signature\SignatureBuilder */
$signature = unserialize(file_get_contents('temp'));
$finalizedSignature = $signature->finalize($signatureValue);

// And finally add the finalized signature back to the container
$container->addSignature($finalizedSignature);
```

## Validating signatures

```php
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\AsiceConfig;

AsiceConfig::setCountryCode('EE'); // In order to not load all 4000 CAs, set country code

$container = new Container('/foobar.asice');

// OPTION 1
$container->validateSignatures(); // Returns array{index: int, valid: bool, errors: ValidationResult[]}

// OPTION 2
$i = 0;
foreach ($container->getSignatures() as $sig) {
    $valid = $sig->isValid();
    var_dump($i . ': ' . ($valid ? 'OK' : 'NOK'));
    if (!$valid) var_dump($sig->getValidationErrors());
    $i++;
}
```

## Best practices

It’s best to load the LOTL once at application startup and cache it (e.g. in Redis, file, or database) to avoid repeated network requests and long initialization times.<br>
It is recommended to update LOTL every 24h.

```php
use Vatsake\AsicE\Validation\Lotl;
use Vatsake\AsicE\AsiceConfig;

// Bootstrap
Lotl::refresh(); // This force loads all trust anchors (without country code its about 4.5k)
$lotl = AsiceConfig::getLotl(); // Returns array of trust anchors
file_put_contents('foo', json_encode($lotl)); // Your application might have a cache server

// Subsequent requests
$lotl = json_decode(file_get_contents('foo'), true);
AsiceConfig::setLotl($lotl)
  ->setOcspUrl(/* OCSP URL */) // Also set these
  ->setTsaUrl(/* TSA URL */)
  ->setCountryCode('EE'); // If you filter trust anchors by country code, it's best to add this as well
```

NB! If not filtering by country code, be aware that holding 4.5k certificates in memory is resource-intensive and can significantly impact performance - especially during startup.

## Requirements

- PHP 8.1 or higher
- OpenSSL extension enabled
- DOM and XML extensions

## License

MIT © Vatsake
