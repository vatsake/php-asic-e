<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Exceptions;

class Asn1Exception extends \Exception
{
    public function __construct(string $message = 'ASN1 encoding/decoding fault')
    {
        parent::__construct($message);
    }
}
