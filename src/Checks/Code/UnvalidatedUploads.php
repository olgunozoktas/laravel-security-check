<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** A stored upload in a file that never checks the file's type: a user can upload a .php or an .html file. */
final class UnvalidatedUploads extends BaseCheck
{
    private const STORE = '/->(?:store|storeAs|storePublicly|storePubliclyAs|move)\s*\(/';

    private const UPLOAD = '/->file\(|UploadedFile|WithFileUploads|TemporaryUploadedFile|->hasFile\(/';

    private const TYPE_RULE = '/mimes:|mimetypes:|[\'"|]image[\'"|]|extensions:|File::types|File::image|Rule::imageFile|->extensions\(|->types\(/';

    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->files->list(['app'], ['.php']) as $file) {
            $text = $context->files->text($file);
            if (preg_match(self::UPLOAD, $text) !== 1 || preg_match(self::TYPE_RULE, $text) === 1) {
                continue;
            }
            foreach ($context->files->grep([$file], self::STORE) as [, $line, $code]) {
                $out[] = $this->finding(Severity::Low, 'An upload is stored, and this file checks no file type (mimes, mimetypes, image, File::types).',
                    'Validate the upload\'s type and size first: [\'file\' => [\'required\', \'file\', \'mimes:pdf,jpg,png\', \'max:10240\']]; never store it under public/ with its own name. (The rules may live in a Form Request: then this is a false finding.)', $file, $line, $code);
            }
        }

        return $out;
    }
}
