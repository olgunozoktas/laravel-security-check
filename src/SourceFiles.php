<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

use FilesystemIterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The app's own source files, read once.
 *
 * `vendor`, `node_modules`, `storage` and `.git` are skipped AT ANY DEPTH: a package's own test fixtures hold the very
 * shapes the checks look for (the livewire-security scanner measured 49 false findings from `packages/*\/vendor`).
 * `count()` says how many files were read, so "no findings" never hides "read nothing".
 */
final class SourceFiles
{
    private const SKIP = ['vendor', 'node_modules', 'storage', '.git', 'bootstrap/cache'];

    /** @var array<string, list<string>> */
    private array $lines = [];

    /** @var array<string, list<string>> */
    private array $lists = [];

    /** A file over this size is data, not code (a 20 MB JSON seed file in one real app): it is skipped and counted. */
    public const MAX_BYTES = 1_000_000;

    /** @var array<string, true> */
    private array $large = [];

    public function __construct(private readonly string $base) {}

    /**
     * Relative paths of the files under `$dirs` whose names end with one of `$suffixes`.
     *
     * @param  list<string>  $dirs
     * @param  list<string>  $suffixes
     * @return list<string>
     */
    public function list(array $dirs, array $suffixes): array
    {
        $key = implode(',', $dirs).'|'.implode(',', $suffixes);
        if (isset($this->lists[$key])) {
            return $this->lists[$key];
        }

        $out = [];
        foreach ($dirs as $dir) {
            $root = $this->base.'/'.$dir;
            if (! is_dir($root)) {
                continue;
            }
            $filter = new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                static fn (SplFileInfo $entry): bool => ! $entry->isDir() || ! in_array($entry->getFilename(), ['vendor', 'node_modules', '.git', 'storage'], true),
            );
            foreach (new RecursiveIteratorIterator($filter) as $file) {
                if (! $file instanceof SplFileInfo) {
                    continue;
                }
                $relative = ltrim(substr($file->getPathname(), strlen($this->base)), '/');
                if ($file->getSize() > self::MAX_BYTES) {
                    $this->large[$relative] = true;

                    continue;
                }
                foreach ($suffixes as $suffix) {
                    if (str_ends_with($relative, $suffix)) {
                        $out[] = $relative;
                        break;
                    }
                }
            }
        }
        sort($out);

        return $this->lists[$key] = array_values(array_unique($out));
    }

    /** @return list<string> */
    public function lines(string $relative): array
    {
        return $this->lines[$relative] ??= explode("\n", (string) @file_get_contents($this->base.'/'.$relative));
    }

    public function text(string $relative): string
    {
        return implode("\n", $this->lines($relative));
    }

    public function exists(string $relative): bool
    {
        return file_exists($this->base.'/'.$relative);
    }

    /** How many files were skipped as larger than MAX_BYTES. */
    public function largeCount(): int
    {
        return count($this->large);
    }

    /** How many files the checks read. */
    public function count(): int
    {
        return count($this->lines);
    }

    /**
     * Each line of `$files` that matches `$pattern`: [file, line number, text].
     *
     * @param  list<string>  $files
     * @return list<array{0: string, 1: int, 2: string}>
     */
    public function grep(array $files, string $pattern): array
    {
        $hits = [];
        foreach ($files as $file) {
            foreach ($this->lines($file) as $i => $line) {
                if (preg_match($pattern, $line) === 1) {
                    $hits[] = [$file, $i + 1, $line];
                }
            }
        }

        return $hits;
    }
}
