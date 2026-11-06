<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

/** The report as text (grouped by severity, `file:line` first so a terminal makes it clickable) or as JSON. */
final class Report
{
    /**
     * @param  list<Finding>  $findings
     * @param  list<string>  $skipped
     */
    public function __construct(private readonly array $findings, private readonly array $skipped, private readonly int $checks, private readonly int $files, private readonly int $large = 0) {}

    /** @return array<string, int> */
    public function counts(): array
    {
        $counts = ['high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach ($this->findings as $f) {
            $counts[$f->severity->value]++;
        }

        return $counts;
    }

    public function failsAt(Severity $floor): bool
    {
        foreach ($this->findings as $f) {
            if ($f->severity->rank() >= $floor->rank()) {
                return true;
            }
        }

        return false;
    }

    public function json(): string
    {
        return (string) json_encode([
            'checks' => $this->checks,
            'files_read' => $this->files,
            'large_files_skipped' => $this->large,
            'skipped' => $this->skipped,
            'counts' => $this->counts(),
            'findings' => array_map(static fn (Finding $f): array => $f->toArray(), $this->findings),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function text(): string
    {
        $out = [];
        foreach ($this->findings as $f) {
            $where = $f->file !== null ? $f->file.($f->line !== null ? ':'.$f->line : '').'  ' : '';
            $out[] = sprintf('%-6s %s[%s] %s', strtoupper($f->severity->value), $where, $f->check, $f->message);
            if ($f->code !== null && $f->code !== '') {
                $out[] = '       '.$f->code;
            }
            $out[] = '       Fix: '.$f->remedy;
            $out[] = '';
        }
        $c = $this->counts();
        $out[] = sprintf('%d checks, %d files read (%d over 1 MB skipped as data), %d checks skipped (%s). Findings: %d high, %d medium, %d low, %d info.',
            $this->checks, $this->files, $this->large, count($this->skipped), $this->skipped === [] ? 'none' : implode(', ', $this->skipped),
            $c['high'], $c['medium'], $c['low'], $c['info']);

        return implode("\n", $out);
    }
}
