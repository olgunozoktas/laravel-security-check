<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Dependencies;

use Illuminate\Support\Facades\Process;
use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** `composer audit --locked`: the installed packages with a known security advisory. It reads the advisory list over the network once. */
final class ComposerAudit extends BaseCheck
{
    public function group(): string { return 'dependencies'; }

    public function applies(Context $context): bool
    {
        return $context->files->exists('composer.lock');
    }

    public function run(Context $context): array
    {
        $composer = trim((string) @shell_exec('command -v composer 2>/dev/null'));
        if ($composer === '') {
            return [$this->finding(Severity::Info, 'composer audit did not run: composer is not on the PATH.', 'Install Composer, or run composer audit in CI.', 'composer.lock')];
        }
        $result = Process::path($context->base())->timeout(90)->run([$composer, 'audit', '--locked', '--format=json', '--no-interaction']);
        $json = json_decode($result->output(), true);
        if (! is_array($json) || ! isset($json['advisories'])) {
            return [$this->finding(Severity::Info, 'composer audit did not answer (no network?): the dependencies were not checked.', 'Run composer audit --locked when the network is there, or in CI.', 'composer.lock', null, trim($result->errorOutput()))];
        }
        $out = [];
        foreach ((array) $json['advisories'] as $package => $advisories) {
            foreach ((array) $advisories as $a) {
                $severity = match (strtolower((string) ($a['severity'] ?? ''))) {
                    'critical', 'high' => Severity::High,
                    'low' => Severity::Low,
                    default => Severity::Medium,
                };
                $out[] = $this->finding($severity, sprintf('%s: %s (%s; versions %s).', $package, $a['title'] ?? 'a known advisory', $a['cve'] ?? $a['advisoryId'] ?? 'no id', $a['affectedVersions'] ?? '?'),
                    "Update it: composer update $package --with-dependencies; read ".($a['link'] ?? 'the advisory').'.', 'composer.lock');
            }
        }

        return $out;
    }
}
