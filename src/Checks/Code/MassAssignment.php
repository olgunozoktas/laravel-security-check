<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** A model that accepts every field, or the whole request written into a model: a user can set is_admin, user_id, price. */
final class MassAssignment extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        $php = $context->files->list(['app'], ['.php']);
        foreach ($context->files->grep($php, '/\$guarded\s*=\s*\[\s*\]/') as [$file, $line, $code]) {
            // Low alone: it is a hole only with unvalidated input, which the $request->all() rule below reports as medium.
            $out[] = $this->finding(Severity::Low, 'The model guards no field ($guarded = []): create() and update() accept every column that they are given.', 'List the fields in $fillable (laravel-best-practices: never $guarded = [] on a model that accepts user input), and write only validated fields into it.', $file, $line, $code);
        }
        foreach ($context->files->grep($php, '/Model::unguard\(\)|::unguard\(\)/') as [$file, $line, $code]) {
            $out[] = $this->finding(Severity::Medium, 'Model::unguard() turns off mass-assignment protection for every model.', 'Remove it from application code (a seeder may keep it inside Model::unguarded(fn () => ...)).', $file, $line, $code);
        }
        foreach ($context->files->grep($php, '/(?:::create|->update|->fill|->forceFill|::forceCreate|->updateOrCreate|::updateOrCreate)\(\s*(?:\[\s*\.\.\.)?\s*\$request->(?:all|input)\(\s*\)/') as [$file, $line, $code]) {
            $out[] = $this->finding(Severity::Medium, 'The whole request is written into a model: a user can add any field to the request.', 'Write only validated fields: $model->update($request->validated()) or $request->only([...]).', $file, $line, $code);
        }

        return $out;
    }
}
