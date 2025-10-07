<?php

declare(strict_types=1);

namespace Vatsake\AsicE;

abstract class Container
{
    private static $instances = [];

    public static function getInstance(): static
    {
        $class = static::class;
        if (!isset(self::$instances[$class])) {
            self::$instances[$class] = new static();
        }
        return self::$instances[$class];
    }

    protected function __clone()
    {
    }

    public function __wakeup()
    {
        throw new \Exception();
    }
}
