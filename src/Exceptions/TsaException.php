<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Exceptions;

class TsaException extends \Exception
{
    public function __construct(string $message)
    {
        parent::__construct($message);
    }
}
