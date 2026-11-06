<?php

declare(strict_types=1);

use Olgun\SecurityCheck\Check;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Finding;
use Olgun\SecurityCheck\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

/**
 * A fixture app: the files (relative path => text) under tests/.work/<unique>, which becomes the app's base path.
 * The folder is removed after the test.
 *
 * @param  array<string, string>  $files
 */
function makeApp(array $files): string
{
    $dir = __DIR__.'/.work/'.bin2hex(random_bytes(6));
    foreach ($files as $path => $text) {
        @mkdir(dirname("$dir/$path"), 0777, true);
        file_put_contents("$dir/$path", $text);
    }
    @mkdir($dir, 0777, true);
    app()->setBasePath($dir);
    test()->beforeApplicationDestroyed(static fn () => removeDir($dir));

    return $dir;
}

function removeDir(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

/**
 * Runs one check on the fixture app: its findings as [severity, file, line] lists, or 'skipped'.
 *
 * @param  class-string<Check>  $class
 * @return list<array{0: string, 1: ?string, 2: ?int}>|string
 */
function check(string $class, array $files = []): array|string
{
    makeApp($files);
    $context = new Context(app());
    $check = app($class);
    if (! $check->applies($context)) {
        return 'skipped';
    }

    return array_map(static fn (Finding $f): array => [$f->severity->value, $f->file, $f->line], $check->run($context));
}

/** @return list<string> the severities of a check's findings */
function severities(array|string $result): array|string
{
    return is_string($result) ? $result : array_map(static fn (array $f): string => $f[0], $result);
}

/** Livewire is "installed" in a fixture by its vendor folder. */
const LIVEWIRE = ['vendor/livewire/livewire/composer.json' => '{}'];
