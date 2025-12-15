<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Crypto;

enum SignAlg: string
{
    case RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    case RSA_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    case RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    case RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    case ECDSA_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224';
    case ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
    case ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
    case ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';

    case ECDSA_SHA3_256 = 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-256';
    case ECDSA_SHA3_384 = 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-384';
    case ECDSA_SHA3_512 = 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-512';

    public function getDigestName()
    {
        return match ($this) {
            self::RSA_SHA1 => 'sha1',
            self::RSA_SHA224, self::ECDSA_SHA224 => 'sha224',
            self::RSA_SHA256, self::ECDSA_SHA256 => 'sha256',
            self::RSA_SHA384, self::ECDSA_SHA384 => 'sha384',
            self::RSA_SHA512, self::ECDSA_SHA512 => 'sha512',
            self::ECDSA_SHA3_256 => 'sha3-256',
            self::ECDSA_SHA3_384 => 'sha3-384',
            self::ECDSA_SHA3_512 => 'sha3-512'
        };
    }

    public static function fromRsaName(string $name): self
    {
        return match (str_replace(['-', '_'], ['', ''], strtolower($name))) {
            'sha1' => self::RSA_SHA1,
            'sha224' => self::RSA_SHA224,
            'sha256' => self::RSA_SHA256,
            'sha384' => self::RSA_SHA384,
            'sha512' => self::RSA_SHA512,
            default => throw new \InvalidArgumentException('Unsupported RSA signature algorithm name: ' . $name),
        };
    }

    public static function fromEcdsaName(string $name): self
    {
        return match (str_replace(['-', '_'], ['', ''], strtolower($name))) {
            'sha224' => self::ECDSA_SHA224,
            'sha256' => self::ECDSA_SHA256,
            'sha384' => self::ECDSA_SHA384,
            'sha512' => self::ECDSA_SHA512,
            'sha3256' => self::ECDSA_SHA3_256,
            'sha3384' => self::ECDSA_SHA3_384,
            'sha3512' => self::ECDSA_SHA3_512,
            default => throw new \InvalidArgumentException('Unsupported ECDSA signature algorithm name: ' . $name),
        };
    }

    public static function fromOid(string $oid): self
    {
        return match ($oid) {
            '1.2.840.113549.1.1.5'  => self::RSA_SHA1,
            '1.2.840.113549.1.1.14' => self::RSA_SHA224,
            '1.2.840.113549.1.1.11' => self::RSA_SHA256,
            '1.2.840.113549.1.1.12' => self::RSA_SHA384,
            '1.2.840.113549.1.1.13' => self::RSA_SHA512,

            '1.2.840.10045.4.3.1' => self::ECDSA_SHA224,
            '1.2.840.10045.4.3.2' => self::ECDSA_SHA256,
            '1.2.840.10045.4.3.3' => self::ECDSA_SHA384,
            '1.2.840.10045.4.3.4' => self::ECDSA_SHA512,

            '2.16.840.1.101.3.4.3.10' => self::ECDSA_SHA3_256,
            '2.16.840.1.101.3.4.3.11' => self::ECDSA_SHA3_384,
            '2.16.840.1.101.3.4.3.12' => self::ECDSA_SHA3_512,

            default => throw new \InvalidArgumentException('Unsupported signature algorithm OID: ' . $oid),
        };
    }
}
