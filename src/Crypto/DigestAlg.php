<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Crypto;

enum DigestAlg: string
{
    case SHA1 = 'sha1';
    case SHA256 = 'sha256';
    case SHA384 = 'sha384';
    case SHA512 = 'sha512';

    // Probably a better way to do this
    private const META = [
        self::SHA1->value   => [
            'oid' => '1.3.14.3.2.26',
            'url' => 'http://www.w3.org/2001/04/xmlenc#sha1',
        ],
        self::SHA256->value => [
            'oid' => '2.16.840.1.101.3.4.2.1',
            'url' => 'http://www.w3.org/2001/04/xmlenc#sha256',
        ],
        self::SHA384->value => [
            'oid' => '2.16.840.1.101.3.4.2.2',
            'url' => 'http://www.w3.org/2001/04/xmlenc#sha384',
        ],
        self::SHA512->value => [
            'oid' => '2.16.840.1.101.3.4.2.3',
            'url' => 'http://www.w3.org/2001/04/xmlenc#sha512',
        ],
    ];

    public function getUrl(): string
    {
        return match ($this) {
            self::SHA1 => self::META[self::SHA1->value]['url'],
            self::SHA256 => self::META[self::SHA256->value]['url'],
            self::SHA384 => self::META[self::SHA384->value]['url'],
            self::SHA512 => self::META[self::SHA512->value]['url'],
        };
    }

    public function getOid(): string
    {
        return match ($this) {
            self::SHA1 => self::META[self::SHA1->value]['oid'],
            self::SHA256 => self::META[self::SHA256->value]['oid'],
            self::SHA384 => self::META[self::SHA384->value]['oid'],
            self::SHA512 => self::META[self::SHA512->value]['oid'],
        };
    }

    public static function fromOid(string $oid): self
    {
        foreach (self::cases() as $enum) {
            if ($enum->getOid() === $oid) {
                return $enum;
            }
        }
        throw new \InvalidArgumentException('Unsupported OID: ' . $oid);
    }

    public static function fromUrl(string $url): self
    {
        foreach (self::cases() as $enum) {
            if ($enum->getUrl() === $url) {
                return $enum;
            }
        }
        throw new \InvalidArgumentException('Unsupported URL: ' . $url);
    }
}
