<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Illuminate\Support\Str;
use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** A route that changes data (POST, PUT, PATCH, DELETE) with no auth, signed or can middleware: anyone can call it. */
final class UnprotectedRoutes extends BaseCheck
{
    private const GUARDS = '/^(auth(:.*)?|auth\.basic.*|can:.*|signed.*|verified|password\.confirm|Illuminate\\\\Auth\\\\Middleware\\\\(Authenticate|Authorize|EnsureEmailIsVerified).*|Illuminate\\\\Routing\\\\Middleware\\\\ValidateSignature.*|.*\\\\Authenticate(Session)?$|abilities:.*|ability:.*|role:.*|permission:.*)$/';

    // Framework routes that guard themselves: Laravel's signed local-storage upload, and Boost's local tools.
    private const FRAMEWORK = ['storage/{path}', 'mcp', 'mcp/*', '_boost/*', 'up'];

    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $public = (array) $context->config('security-check.public_routes', []);
        $out = [];
        foreach ($context->router()->getRoutes()->getRoutes() as $route) {
            $methods = array_intersect($route->methods(), ['POST', 'PUT', 'PATCH', 'DELETE']);
            if ($methods === [] || Str::is([...$public, ...self::FRAMEWORK], $route->uri())) {
                continue;
            }
            $middleware = $route->gatherMiddleware();
            $guarded = array_filter($middleware, static fn ($m): bool => is_string($m) && preg_match(self::GUARDS, $m) === 1);
            if ($guarded !== []) {
                continue;
            }
            $action = $route->getActionName();
            $uri = ltrim($route->uri(), '/');
            // Most public POST routes are public on purpose (a contact form, a token link): low, to confirm. A route that
            // signs someone in, or that changes an account, a payment or a user, is medium; a back door to log in is high.
            $severity = preg_match('/dev-?login|impersonat|sudo|login-?as/i', $uri.' '.$action) === 1 ? Severity::High
                : (preg_match('/admin|billing|account|settings|users?\b|\bdelete|destroy|payment|subscription|role|permission/i', $uri.' '.$action) === 1 ? Severity::Medium : Severity::Low);
            $out[] = $this->finding($severity, sprintf('%s /%s has no auth, signed or can middleware: anyone can call it (%s).', implode('|', $methods), $uri, $action),
                'Add ->middleware(\'auth\') (or can:, signed), or add its URI to security-check.public_routes when it is public on purpose (a webhook with its own signature check).', 'routes');
        }

        return $out;
    }
}
