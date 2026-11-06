<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** A login form with no rate limit: a password can be guessed without end. */
final class LoginThrottle extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        // Starter kits limit the login inside the form request or the Livewire form (LoginRequest::ensureIsNotRateLimited).
        if ($context->files->grep($context->files->list(['app', 'resources/views'], ['.php']), '/RateLimiter::(?:tooManyAttempts|attempt|hit)\(|ensureIsNotRateLimited/') !== []) {
            return [];
        }
        $out = [];
        foreach ($context->router()->getRoutes()->getRoutes() as $route) {
            if (! in_array('POST', $route->methods(), true) || ! preg_match('/(^|\/)(login|two-factor-challenge)$/', $route->uri())) {
                continue;
            }
            $middleware = implode(',', array_filter($route->gatherMiddleware(), 'is_string'));
            if (str_contains($middleware, 'throttle')) {
                continue;
            }
            // Fortify limits its own login route through a named limiter.
            if (str_contains($route->getActionName(), 'Laravel\\Fortify') && $context->config('fortify.limiters.login')) {
                continue;
            }
            $out[] = $this->finding(Severity::Medium, "POST /{$route->uri()} has no rate limit: passwords can be guessed without end.",
                'Add ->middleware(\'throttle:5,1\') (or a RateLimiter), or set fortify.limiters.login.', 'routes');
        }

        return $out;
    }
}
