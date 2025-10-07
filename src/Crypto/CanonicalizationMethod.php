<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Crypto;

use InvalidArgumentException;

enum CanonicalizationMethod: string
{
    case INCLUSIVE_1_0 = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    case INCLUSIVE_1_0_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    case EXCLUSIVE_1_0 = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    case EXCLUSIVE_1_0_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    case INCLUSIVE_1_1 = 'http://www.w3.org/2006/12/xml-c14n11#';
    case INCLUSIVE_1_1_COMMENTS = 'http://www.w3.org/2006/12/xml-c14n11#WithComments';

    public function exclusive(): bool
    {
        return match ($this) {
            self::EXCLUSIVE_1_0 => true,
            self::EXCLUSIVE_1_0_COMMENTS => true,
            default => false
        };
    }

    public function withComments(): bool
    {
        return str_contains($this->value, 'WithComments');
    }

    /**
     * Normalises canonicalisation URIs – some signatures omit the trailing '#'
     *
     * Compare both the full value and the fragment-less form
     */
    public static function tryFromUrl(string $url): self
    {
        foreach (self::cases() as $case) {
            if ($case->value === $url) {
                return $case;
            }
        }

        $base = str_ends_with($url, '#') ? explode('#', $url)[0] : $url;
        foreach (self::cases() as $canon) {
            $compareUrl = str_ends_with($canon->value, '#') ? explode('#', $canon->value)[0] : $canon->value;
            if ($compareUrl === $base) {
                return $canon;
            }
        }
        throw new \InvalidArgumentException('Invalid canonicalization method ' . $url);
    }
}
