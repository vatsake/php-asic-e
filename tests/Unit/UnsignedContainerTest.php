<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vatsake\AsicE\Container\UnsignedContainer;
use Vatsake\AsicE\Container\Container;
use Vatsake\AsicE\Exceptions\ContainerAlreadyFinalized;

class UnsignedContainerTest extends TestCase
{
    public function testAddFile()
    {
        $container = new UnsignedContainer();
        $container->addFile('test.txt', 'This is a test file.');

        $files = $container->getFiles();
        $this->assertCount(1, $files);
        $this->assertArrayHasKey('test.txt', $files);
    }

    public function testBuildCreatesContainer()
    {
        $container = new UnsignedContainer();
        $container->addFile('test.txt', 'This is a test file.');

        $tempPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-container-1.asice';
        $builtContainer = $container->build($tempPath);

        $this->assertInstanceOf(Container::class, $builtContainer);
        $this->assertFileExists($tempPath);

        unlink($tempPath);
    }

    public function testCannotAddFileAfterBuild()
    {
        $this->expectException(ContainerAlreadyFinalized::class);

        $container = new UnsignedContainer();
        $container->addFile('test.txt', 'This is a test file.');

        $tempPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-container-2.asice';
        $container->build($tempPath);
        unlink($tempPath);

        $container->addFile('another.txt', 'This should fail.');
    }

    public function testCannotBuildTwice()
    {
        $this->expectException(ContainerAlreadyFinalized::class);

        $container = new UnsignedContainer();
        $container->addFile('test.txt', 'This is a test file.');

        $tempPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-container-3.asice';
        $container->build($tempPath);
        unlink($tempPath);

        $container->build($tempPath);
    }
}
