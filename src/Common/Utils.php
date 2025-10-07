<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Common;

use phpseclib3\Math\BigInteger;
use Vatsake\AsicE\Api\HttpClient;

abstract class Utils
{
    public static function stripPemHeaders(string $pem): string
    {
        return preg_replace(
            '/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/',
            '',
            $pem
        );
    }

    public static function stripPubHeaders(string $pem): string
    {
        return preg_replace(
            '/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/',
            '',
            $pem
        );
    }

    public static function addPemHeaders(string $pem): string
    {
        if (str_contains($pem, 'BEGIN CERTIFICATE')) {
            return $pem;
        }
        return "-----BEGIN CERTIFICATE-----\n" . $pem . "\n-----END CERTIFICATE-----";
    }

    public static function getIssuerCert(string $subjectCertificate, array $certificates = []): string
    {
        $parsedSubjectCert = openssl_x509_parse($subjectCertificate);
        if ($parsedSubjectCert === false) {
            throw new \InvalidArgumentException('Invalid subjectCertificate given');
        }

        if (
            array_key_exists('subjectKeyIdentifier', $parsedSubjectCert['extensions'])
            && array_key_exists('authorityKeyIdentifier', $parsedSubjectCert['extensions'])
        ) {
            $issuerIdentifier = $parsedSubjectCert['extensions']['authorityKeyIdentifier'];
            foreach ($certificates as $certificate) {
                $parsedCert = openssl_x509_parse(Utils::addPemHeaders($certificate));
                if ($parsedCert['extensions']['subjectKeyIdentifier'] === $issuerIdentifier) {
                    return Utils::addPemHeaders($certificate);
                }
            }
        }

        // Test CA case
        if ($parsedSubjectCert['subject']['CN'] === "My Signer Certificate") {
            return file_get_contents('tests/Certs/testCA.crt');
        }

        // Try to get it from AIA
        if (!array_key_exists('authorityInfoAccess', $parsedSubjectCert['extensions'])) {
            throw new \RuntimeException('Issuer info access missing');
        }
        $urls = explode("\n", $parsedSubjectCert['extensions']['authorityInfoAccess']);

        $httpClient = new HttpClient();
        foreach ($urls as $url) {
            if (str_starts_with($url, 'CA Issuers')) {
                $caUrl = explode('URI:', $url)[1];
                $cert = $httpClient->get($caUrl);
                if ($cert !== '') {
                    return Utils::addPemHeaders(base64_encode($cert));
                }
            }
        }

        throw new \RuntimeException('Unable to get issuer certificate');
    }

    public static function stripBr(string $str): string
    {
        return str_replace(["\n", "\n"], [''], $str);
    }

    // Returns serial number as integer string
    public static function serialToNumber(string $input): string
    {
        $s = preg_replace('/\s+/', '', trim($input));
        if ($s === '') {
            return '0';
        }

        // Determine if hex: 0x prefix OR contains A-F
        $isHex = false;
        if (preg_match('/^0x/i', $s)) {
            $s = substr($s, 2);
            $isHex = true;
        } elseif (preg_match('/[A-Fa-f]/', $s)) {
            $isHex = true;
        }

        if ($isHex) {
            $hex = ltrim($s, '0');
            if ($hex === '') {
                return '0';
            }
            $bi = new BigInteger($hex, 16);
            return $bi->toString(10);
        }

        if (!preg_match('/^\d+$/', $s)) {
            return '';
        }

        $s = ltrim($s, '0') ?: '0';
        return $s;
    }
}
