<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Exceptions;

class InvalidCertificateException extends \Exception
{
    public function __construct(string $message = 'Invalid certificate', string $certificate = '')
    {
        parent::__construct($message . ($certificate ? ' [' . $certificate . ']' : ''));
    }
}
