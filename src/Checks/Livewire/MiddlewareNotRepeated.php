<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/**
 * A Livewire page behind `permission:`, `role:` or `password.confirm`: those do not run again on Livewire's update endpoint
 * (only the persistent list does: Authenticate, Authorize, SubstituteBindings, Sanctum, Jetstream), so each later action
 * skips that check (livewire-security, rule 5).
 */
final class MiddlewareNotRepeated extends LivewireCheck
{
    private const NOT_PERSISTENT = '/^(permission:|role:|role_or_permission:|password\.confirm|Illuminate\\\\Auth\\\\Middleware\\\\RequirePassword)/';

    public function run(Context $context): array
    {
        $persistent = class_exists(\Livewire\Livewire::class) && method_exists(\Livewire\Livewire::class, 'getPersistentMiddleware')
            ? array_map('strval', (array) \Livewire\Livewire::getPersistentMiddleware()) : [];
        $out = [];
        foreach ($context->router()->getRoutes()->getRoutes() as $route) {
            $action = (string) $route->getActionName();
            $isLivewire = is_subclass_of(explode('@', $action)[0], \Livewire\Component::class) || str_contains($action, 'Livewire');
            if (! $isLivewire) {
                continue;
            }
            foreach (array_filter($route->gatherMiddleware(), 'is_string') as $middleware) {
                if (preg_match(self::NOT_PERSISTENT, $middleware) === 1 && ! in_array(explode(':', $middleware)[0], $persistent, true)) {
                    $out[] = $this->finding(Severity::Medium, "/{$route->uri()} is a Livewire page behind \"$middleware\", which does not run again on the update endpoint: a later action skips that check.",
                        'Check it again inside each action ($this->authorize(...)), or register the middleware with Livewire::addPersistentMiddleware().', 'routes', null, $middleware);
                }
            }
        }

        return $out;
    }
}
