<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api;

interface HttpRequest
{
    public function getBody(): string;

    public function getUrl(): string;
}
