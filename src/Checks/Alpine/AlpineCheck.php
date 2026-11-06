<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Alpine;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;

/** An Alpine check (the alpinejs-security skill): it applies when a Blade view uses Alpine, or the app has Livewire (which bundles it). */
abstract class AlpineCheck extends BaseCheck
{
    public function group(): string { return 'alpine'; }

    public function applies(Context $context): bool
    {
        return $context->hasLivewire() || $context->files->grep($context->bladeFiles(), '/\bx-data\b/') !== [];
    }
}
