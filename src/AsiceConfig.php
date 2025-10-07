<?php

declare(strict_types=1);

namespace Vatsake\AsicE;

final class AsiceConfig extends Container
{
    private ?string $tsaUrl = null;
    private ?string $ocspUrl = null;
    private ?string $countryCode = null;
    private array $lotl = [];

    public static function getTsaUrl(): ?string
    {
        return self::getInstance()->tsaUrl;
    }

    public static function setTsaUrl(string $tsaUrl): self
    {
        $instance = self::getInstance();
        $instance->tsaUrl = $tsaUrl;
        return $instance;
    }

    public static function getOcspUrl(): ?string
    {
        return self::getInstance()->ocspUrl;
    }

    public static function setOcspUrl(string $ocspUrl): self
    {
        $instance = self::getInstance();
        $instance->ocspUrl = $ocspUrl;
        return $instance;
    }

    public static function getCountryCode(): ?string
    {
        return self::getInstance()->countryCode;
    }

    public static function setCountryCode(?string $countryCode): self
    {
        $instance = self::getInstance();
        $instance->countryCode = $countryCode;
        return $instance;
    }

    public static function getLotl(): array
    {
        return self::getInstance()->lotl;
    }

    public static function setLotl(array $lotl): self
    {
        $instance = self::getInstance();
        $instance->lotl = $lotl;
        return $instance;
    }

    /**
     * @param array{tsaUrl?: string, ocspUrl?: string, lotlCountryCode?: string, lotl?: array<string>} $cfg
     */
    public static function fromArray(array $cfg)
    {
        $self = self::getInstance();
        $self->tsaUrl = $cfg['tsaUrl'] ?? null;
        $self->ocspUrl = $cfg['ocspUrl'] ?? null;
        $self->countryCode = $cfg['lotlCountryCode'] ?? null;
        $self->lotl = $cfg['lotl'] ?? [];
    }
}
