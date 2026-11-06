<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** The session cookie: never readable by scripts, only over HTTPS in production, and not sent by other sites. */
final class SessionCookies extends BaseCheck
{
    public function group(): string { return 'config'; }

    public function run(Context $context): array
    {
        $out = [];
        if ($context->config('session.http_only') === false) {
            $out[] = $this->finding(Severity::High, 'session.http_only is false: a script on the page (an XSS) can read the session cookie.', 'Set http_only to true in config/session.php.', 'config/session.php');
        }
        if ($context->production() && ! $context->config('session.secure')) {
            $out[] = $this->finding(Severity::High, 'session.secure is off in production: the session cookie can travel over plain HTTP.', 'Set SESSION_SECURE_COOKIE=true in production\'s .env.', 'config/session.php');
        }
        $same = $context->config('session.same_site');
        if ($same === null || strtolower((string) $same) === 'none') {
            $out[] = $this->finding(Severity::Medium, 'session.same_site is '.($same === null ? 'null' : 'none').': other sites can send requests with the user\'s session.', 'Set same_site to "lax" (or "strict") in config/session.php.', 'config/session.php');
        }

        return $out;
    }
}
