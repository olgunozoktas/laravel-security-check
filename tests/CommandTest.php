<?php

declare(strict_types=1);

use Olgun\SecurityCheck\CheckRegistry;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\SourceFiles;

it('exits 1 at or above --fail-on, 0 below it, and 2 for a wrong value', function () {
    makeApp(['app/A.php' => "<?php\n\$k = env('A');\n"]);  // one low finding (env-outside-config)
    config(['app.key' => 'base64:'.base64_encode(random_bytes(32)), 'app.debug' => false]);
    $this->artisan('security:check', ['--only' => 'env-outside-config', '--fail-on' => 'medium'])->assertExitCode(0);
    $this->artisan('security:check', ['--only' => 'env-outside-config', '--fail-on' => 'low'])->assertExitCode(1);
    $this->artisan('security:check', ['--fail-on' => 'severe'])->assertExitCode(2);
});

it('answers JSON with the counts and the findings', function () {
    makeApp(['app/A.php' => "<?php\n\$k = env('A');\n"]);
    Illuminate\Support\Facades\Artisan::call('security:check', ['--only' => 'code', '--json' => true]);
    $json = json_decode(Illuminate\Support\Facades\Artisan::output(), true);
    expect($json['counts']['low'])->toBe(1)
        ->and($json['findings'][0]['check'])->toBe('env-outside-config')
        ->and($json['files_read'])->toBeGreaterThan(0);
});

it('reports a check that throws as a finding, never as a pass', function () {
    makeApp([]);
    $broken = new class extends Olgun\SecurityCheck\BaseCheck {
        public function group(): string { return 'code'; }
        public function run(Context $context): array { throw new RuntimeException('boom'); }
    };
    [$findings] = (new CheckRegistry())->run([$broken], new Context(app()));
    expect($findings)->toHaveCount(1)->and($findings[0]->message)->toContain('The check failed: boom');
});

it('skips a file over 1 MB as data, and counts it', function () {
    makeApp(['database/data/big.json' => str_repeat('x', SourceFiles::MAX_BYTES + 1), 'database/seed.php' => '<?php']);
    $files = new SourceFiles(app()->basePath());
    expect($files->list(['database'], ['.json', '.php']))->toBe(['database/seed.php'])->and($files->largeCount())->toBe(1);
});

it('finds every check file on disk, and nothing else', function () {
    makeApp([]);
    $onDisk = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../src/Checks', FilesystemIterator::SKIP_DOTS)) as $f) {
        $class = 'Olgun\\SecurityCheck\\Checks\\'.str_replace('/', '\\', substr($f->getPathname(), strlen(__DIR__.'/../src/Checks/'), -4));
        if (class_exists($class) && ! (new ReflectionClass($class))->isAbstract() && is_subclass_of($class, Olgun\SecurityCheck\Check::class)) {
            $onDisk[] = $class;
        }
    }
    $found = array_map(static fn ($c): string => $c::class, (new CheckRegistry())->all(new Context(app())));
    sort($onDisk);
    sort($found);
    expect($found)->toBe($onDisk)->and(count($found))->toBe(31);
});
