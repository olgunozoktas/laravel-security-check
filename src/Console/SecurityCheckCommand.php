<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Console;

use Illuminate\Console\Command;
use Olgun\SecurityCheck\CheckRegistry;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Report;
use Olgun\SecurityCheck\Severity;

/**
 * `php artisan security:check`: reads the app and changes nothing. Exit 1 when a finding is at or above --fail-on
 * (default: medium), else 0; exit 2 for a wrong option.
 */
final class SecurityCheckCommand extends Command
{
    protected $signature = 'security:check
        {--only= : Comma-separated groups (config, code, livewire, dependencies) or check names}
        {--fail-on=medium : The lowest severity that exits 1: high, medium, low or info}
        {--json : The report as JSON}';

    protected $description = 'Check the app for security problems, without AI and without changing anything';

    public function handle(CheckRegistry $registry): int
    {
        $floor = Severity::tryFrom((string) $this->option('fail-on'));
        if ($floor === null) {
            $this->error('--fail-on must be high, medium, low or info.');

            return 2;
        }

        $context = new Context($this->laravel);
        $checks = $registry->all($context);
        $only = array_filter(array_map('trim', explode(',', (string) $this->option('only'))));
        if ($only !== []) {
            $checks = array_values(array_filter($checks, static fn ($c): bool => in_array($c->group(), $only, true) || in_array($c->name(), $only, true)));
        }

        [$findings, $skipped] = $registry->run($checks, $context);
        $report = new Report($findings, $skipped, count($checks), $context->files->count(), $context->files->largeCount());
        $this->line($this->option('json') ? $report->json() : $report->text());

        return $report->failsAt($floor) ? 1 : 0;
    }
}
