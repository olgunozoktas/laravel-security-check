<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Livewire;

use Olgun\SecurityCheck\Context;

/**
 * The app's Livewire components, as source: class components (`app/`) and single-file or Volt components
 * (`resources/views`, `new class extends Component`). The rules follow the livewire-security skill's scanner
 * (bin/scan.php, verified on livewire/livewire v4.4.2), including its lessons: a lifecycle hook is not a mutator, and
 * an application's own `ensure*` / `guard*` helper, or a helper of the same class that authorizes, is authorization.
 */
final class Components
{
    public const GUARD = '/\$this->authorize|Gate::|->can\(|->cannot\(|abort_unless|abort_if|::assert\(|policy\(|\$this->ensure\w*\(|\$this->guard\w*\(|::authorize\(|#\[Authorize/';

    /** @return list<string> the relative paths of the files that hold a component */
    public static function files(Context $context): array
    {
        $out = [];
        foreach ($context->files->list(['app', 'resources/views'], ['.php']) as $file) {
            $text = $context->files->text($file);
            if (preg_match('/\bextends\s+(?:\\\\?Livewire\\\\(?:Volt\\\\)?)?Component\b/', $text) === 1 || str_contains($text, 'new class extends Component')) {
                $out[] = $file;
            }
        }

        return $out;
    }

    /**
     * Each public, non-static property declaration of a component file: [line number, type, name, line text, the two lines above].
     *
     * @param  list<string>  $lines
     * @return list<array{0: int, 1: string, 2: string, 3: string, 4: string}>
     */
    public static function publicProperties(array $lines): array
    {
        $out = [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^\s*public\s+(?:readonly\s+)?(\??[\w\\\\|]+)?\s*\$(\w+)/', $line, $m) === 1 && ! str_contains($line, 'function')) {
                $above = ($i > 0 ? $lines[$i - 1] : '')."\n".($i > 1 ? $lines[$i - 2] : '');
                $out[] = [$i + 1, trim((string) ($m[1] ?? ''), '?'), $m[2], trim($line), $above];
            }
        }

        return $out;
    }

    /** @param list<string> $lines @return array<string, string> each method's name (lower case) and up to 40 lines of its body */
    public static function bodies(array $lines): array
    {
        $bodies = [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^\s*(?:public|protected|private)\s+(?:static\s+)?function\s+(\w+)\s*\(/', $line, $m) === 1) {
                $bodies[strtolower($m[1])] = implode("\n", array_slice($lines, $i, 40));
            }
        }

        return $bodies;
    }

    public const PERSIST = '/->(?:delete|forceDelete|save|update|create|insert|upsert|increment|decrement|attach|detach|sync|associate|dissociate|restore|push)\s*\(|::(?:create|destroy|insert|upsert|updateOrCreate|firstOrCreate)\s*\(|DB::|->refund\(|->charge\(/';

    /** Does this body write to the database, itself or through a helper of the same class that it calls? */
    public static function persists(string $body, array $bodies, int $depth = 2): bool
    {
        if (preg_match(self::PERSIST, $body) === 1) {
            return true;
        }
        if ($depth <= 0 || preg_match_all('/\$this->(\w+)\s*\(/', $body, $calls) === 0) {
            return false;
        }
        foreach (array_unique(array_map('strtolower', $calls[1])) as $name) {
            if (isset($bodies[$name]) && self::persists($bodies[$name], $bodies, $depth - 1)) {
                return true;
            }
        }

        return false;
    }

    /** Is this body authorized, itself or through a helper of the same class that it calls (two levels deep)? */
    public static function guarded(string $body, array $bodies, int $depth = 2): bool
    {
        if (preg_match(self::GUARD, $body) === 1) {
            return true;
        }
        if ($depth <= 0 || preg_match_all('/\$this->(\w+)\s*\(/', $body, $calls) === 0) {
            return false;
        }
        foreach (array_unique(array_map('strtolower', $calls[1])) as $name) {
            if (isset($bodies[$name]) && self::guarded($bodies[$name], $bodies, $depth - 1)) {
                return true;
            }
        }

        return false;
    }
}
