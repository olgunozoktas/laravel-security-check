<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Tests;

use Olgun\SecurityCheck\SecurityCheckServiceProvider;
use Orchestra\Testbench\TestCase as Base;

abstract class TestCase extends Base
{
    protected function getPackageProviders($app): array
    {
        return [SecurityCheckServiceProvider::class];
    }
}
