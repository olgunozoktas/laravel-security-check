<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** A live secret written into the source, or a .env file in git. */
final class SecretsInCode extends BaseCheck
{
    // Shapes of real secrets: Stripe live keys, AWS access keys, private keys, GitHub and Slack tokens.
    private const SECRET = '/(sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,}|whsec_[0-9A-Za-z]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{40,}|xox[bpas]-[0-9A-Za-z-]{20,})/';

    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        $files = $context->files->list(['app', 'config', 'routes', 'database', 'resources'], ['.php', '.js', '.ts', '.vue', '.json']);
        foreach ($context->files->grep($files, self::SECRET) as [$file, $line, $code]) {
            preg_match(self::SECRET, $code, $m);
            $out[] = $this->finding(Severity::High, 'A secret is written into the source ('.substr($m[1], 0, 8).'…).',
                'Revoke it now at its provider (it is in git history), then put the new one in .env and read it through config().', $file, $line, substr($m[1], 0, 8).'…');
        }
        $tracked = @shell_exec('cd '.escapeshellarg($context->base()).' && git ls-files .env .env.production .env.backup 2>/dev/null');
        foreach (array_filter(explode("\n", (string) $tracked)) as $env) {
            $out[] = $this->finding(Severity::High, "$env is committed to git: every secret in it is in the repository's history.",
                "Run git rm --cached $env, add it to .gitignore, and rotate every secret that it holds.", $env);
        }

        return $out;
    }
}
