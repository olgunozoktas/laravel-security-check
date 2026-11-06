<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** Files under public/ that the web server gives to anyone: secrets, a repository, dumps, backups, phpinfo. */
final class PublicFiles extends BaseCheck
{
    private const NAMES = ['.env', '.env.backup', '.env.production', '.git', 'phpinfo.php', 'info.php', 'composer.json', 'composer.lock', 'auth.json'];

    private const SUFFIXES = ['.sql', '.sql.gz', '.bak', '.zip', '.tar.gz', '.log', '.sqlite'];

    public function group(): string { return 'config'; }

    public function run(Context $context): array
    {
        $public = $context->base().'/public';
        if (! is_dir($public)) {
            return [];
        }
        $out = [];
        foreach (self::NAMES as $name) {
            if (file_exists("$public/$name")) {
                $out[] = $this->finding(Severity::High, "public/$name can be downloaded by anyone.", "Move public/$name out of public/ (or delete it), and check the web server's logs for downloads of it.", "public/$name");
            }
        }
        foreach ((array) @scandir($public) as $name) {
            foreach (self::SUFFIXES as $suffix) {
                if (is_string($name) && str_ends_with(strtolower($name), $suffix) && is_file("$public/$name")) {
                    $out[] = $this->finding(Severity::High, "public/$name looks like a dump, a backup or a log, and anyone can download it.", "Move public/$name out of public/.", "public/$name");
                }
            }
        }

        return $out;
    }
}
