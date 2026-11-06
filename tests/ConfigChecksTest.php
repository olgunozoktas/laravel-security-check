<?php

declare(strict_types=1);

use Olgun\SecurityCheck\Checks\Config;

it('reports APP_DEBUG outside local, as high in production', function () {
    config(['app.debug' => true]);
    app()['env'] = 'production';
    expect(severities(check(Config\DebugMode::class)))->toBe(['high']);
    app()['env'] = 'staging';
    expect(severities(check(Config\DebugMode::class)))->toBe(['medium']);
    app()['env'] = 'local';
    expect(check(Config\DebugMode::class))->toBe([]);
});

it('reports an empty or short APP_KEY and accepts a 32-byte one', function () {
    config(['app.key' => '']);
    expect(severities(check(Config\AppKey::class)))->toBe(['high']);
    config(['app.key' => 'base64:'.base64_encode(str_repeat('a', 16))]);
    expect(severities(check(Config\AppKey::class)))->toBe(['high']);
    config(['app.key' => 'base64:'.base64_encode(random_bytes(32))]);
    expect(check(Config\AppKey::class))->toBe([]);
});

it('reports session cookies that scripts can read, plain HTTP in production and same_site none', function () {
    app()['env'] = 'production';
    config(['session.http_only' => false, 'session.secure' => false, 'session.same_site' => 'none']);
    expect(severities(check(Config\SessionCookies::class)))->toBe(['high', 'high', 'medium']);
    config(['session.http_only' => true, 'session.secure' => true, 'session.same_site' => 'lax']);
    expect(check(Config\SessionCookies::class))->toBe([]);
});

it('reports CORS for every origin, high with credentials', function () {
    config(['cors' => ['paths' => ['api/*'], 'allowed_origins' => ['*'], 'supports_credentials' => true]]);
    expect(severities(check(Config\Cors::class)))->toBe(['high']);
    config(['cors.supports_credentials' => false]);
    expect(severities(check(Config\Cors::class)))->toBe(['low']);
    config(['cors.allowed_origins' => ['https://example.test']]);
    expect(check(Config\Cors::class))->toBe([]);
});

it('reports secrets, dumps and backups under public/', function () {
    $found = check(Config\PublicFiles::class, ['public/.env' => 'X=1', 'public/dump.sql' => '--', 'public/index.php' => '<?php']);
    expect(array_column($found, 1))->toBe(['public/.env', 'public/dump.sql']);
    expect(check(Config\PublicFiles::class, ['public/index.php' => '<?php']))->toBe([]);
});

it('reports an http APP_URL only in production', function () {
    config(['app.url' => 'http://example.test']);
    app()['env'] = 'production';
    expect(severities(check(Config\HttpsInProduction::class)))->toBe(['medium']);
    app()['env'] = 'local';
    expect(check(Config\HttpsInProduction::class))->toBe('skipped');
});

it('reports a debug tool in require, never in require-dev', function () {
    expect(severities(check(Config\DevToolsInProduction::class, ['composer.json' => '{"require":{"barryvdh/laravel-debugbar":"^3"}}'])))->toBe(['medium']);
    expect(check(Config\DevToolsInProduction::class, ['composer.json' => '{"require-dev":{"barryvdh/laravel-debugbar":"^3"}}']))->toBe([]);
});
