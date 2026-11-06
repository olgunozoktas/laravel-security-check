<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use SplFileInfo;
use Throwable;

/**
 * Finds every check on disk: the package's own (`src/Checks/**`) and the app's (`security-check.checks_path`, default
 * `app/SecurityChecks`). The file being there and the check running are one fact. A check that cannot be built or that
 * throws is reported as an error finding, never a crash and never a silent pass.
 */
final class CheckRegistry
{
    /** @return list<Check> */
    public function all(Context $context): array
    {
        $classes = $this->discover(__DIR__.'/Checks', 'Olgun\\SecurityCheck\\Checks');
        $own = (string) $context->config('security-check.checks_path', 'app/SecurityChecks');
        $classes = [...$classes, ...$this->discover($context->base().'/'.$own, (string) $context->config('security-check.checks_namespace', 'App\\SecurityChecks'))];

        $checks = [];
        foreach ($classes as $class) {
            try {
                $instance = $context->app->make($class);
            } catch (Throwable) {
                continue;
            }
            if ($instance instanceof Check) {
                $checks[] = $instance;
            }
        }
        usort($checks, static fn (Check $a, Check $b): int => [$a->group(), $a->name()] <=> [$b->group(), $b->name()]);

        return $checks;
    }

    /** @return list<class-string> */
    private function discover(string $dir, string $namespace): array
    {
        if (! is_dir($dir)) {
            return [];
        }
        $out = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr($file->getPathname(), strlen($dir) + 1, -4);
            $class = $namespace.'\\'.str_replace('/', '\\', $relative);
            if (! class_exists($class)) {
                require_once $file->getPathname();
            }
            if (class_exists($class) && ! (new ReflectionClass($class))->isAbstract()) {
                $out[] = $class;
            }
        }
        sort($out);

        return $out;
    }

    /**
     * Runs the checks: [findings, skipped check names].
     *
     * @param  list<Check>  $checks
     * @return array{0: list<Finding>, 1: list<string>}
     */
    public function run(array $checks, Context $context): array
    {
        $findings = [];
        $skipped = [];
        foreach ($checks as $check) {
            try {
                if (! $check->applies($context)) {
                    $skipped[] = $check->name();

                    continue;
                }
                array_push($findings, ...$check->run($context));
            } catch (Throwable $e) {
                $findings[] = new Finding($check->name(), Severity::Medium, 'The check failed: '.$e->getMessage(), 'Report it; this check did not run, so it proves nothing.');
            }
        }
        usort($findings, static fn (Finding $a, Finding $b): int => [$b->severity->rank(), $a->check, $a->file ?? '', $a->line ?? 0] <=> [$a->severity->rank(), $b->check, $b->file ?? '', $b->line ?? 0]);

        return [$findings, $skipped];
    }
}
