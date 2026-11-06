<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;

/** What a check may read: the app's base path, its environment, its config, its routes and its source files. */
final class Context
{
    public readonly SourceFiles $files;

    public function __construct(public readonly Application $app)
    {
        $this->files = new SourceFiles(rtrim($app->basePath(), '/'));
    }

    public function base(): string
    {
        return rtrim($this->app->basePath(), '/');
    }

    public function environment(): string
    {
        return (string) $this->app->environment();
    }

    public function production(): bool
    {
        return $this->app->environment('production');
    }

    public function config(string $key, mixed $default = null): mixed
    {
        return $this->app['config']->get($key, $default);
    }

    public function router(): Router
    {
        return $this->app['router'];
    }

    /** The packages that composer.json requires for every environment (not require-dev). @return list<string> */
    public function requiredPackages(): array
    {
        $json = json_decode((string) @file_get_contents($this->base().'/composer.json'), true);

        return array_keys(is_array($json['require'] ?? null) ? $json['require'] : []);
    }

    public function hasLivewire(): bool
    {
        return class_exists(\Livewire\Component::class) || $this->files->exists('vendor/livewire/livewire');
    }

    /** PHP files of the app's own code. @return list<string> */
    public function phpFiles(): array
    {
        return $this->files->list(['app', 'routes', 'config', 'database', 'bootstrap'], ['.php']);
    }

    /** @return list<string> */
    public function bladeFiles(): array
    {
        return $this->files->list(['resources/views'], ['.blade.php']);
    }
}
