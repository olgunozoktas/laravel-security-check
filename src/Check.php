<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

/**
 * One security question, asked without AI and without changing anything.
 *
 * ADDING A CHECK IS ONE FILE: a class in `src/Checks/<Group>/` (or in the app's `app/SecurityChecks/`) that implements
 * this interface. The registry finds it on disk; nothing is registered by hand, so a check cannot exist and not run.
 *
 * A CHECK MUST NOT CHANGE ANYTHING: it reads config, routes and files, and never writes, migrates or sends.
 */
interface Check
{
    /** A stable machine name: `--only=` and the JSON output use it. */
    public function name(): string;

    /** `config`, `code`, `livewire` or `dependencies`. */
    public function group(): string;

    /** False when the check does not apply to this app (it is listed as skipped, never as passed). */
    public function applies(Context $context): bool;

    /** @return list<Finding> */
    public function run(Context $context): array;
}
