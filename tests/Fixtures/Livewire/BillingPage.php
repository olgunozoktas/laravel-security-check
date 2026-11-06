<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Tests\Fixtures\Livewire;

/** A route action whose class name says Livewire, as a Livewire page route's does. */
final class BillingPage
{
    public function __invoke(): string
    {
        return 'billing';
    }
}
