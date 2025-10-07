<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Exceptions;

class ContainerAlreadyFinalized extends \Exception
{
    public function __construct()
    {
        parent::__construct('Container has already been built.');
    }
}
