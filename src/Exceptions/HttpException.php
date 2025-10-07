<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Exceptions;

class HttpException extends \Exception
{
    public function __construct(string $url, string $method, int $httpCode, string $message = '')
    {
        parent::__construct("HTTP request failed: [{$httpCode}] {$method} {$url} {$message}");
    }
}
