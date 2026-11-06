<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Olgun\SecurityCheck\Checks\Code;

it('reports raw SQL from request data as high, a built fragment as low, and a binding not at all', function () {
    $php = "<?php\n"
        ."DB::select(\"select * from users where name = '{\$request->name}'\");\n"
        ."\$q->whereRaw('not '.\$sql, \$bindings);\n"
        ."\$q->whereRaw('price > ?', [\$price]);\n";
    expect(check(Code\RawSql::class, ['app/Q.php' => $php]))->toBe([['high', 'app/Q.php', 2], ['low', 'app/Q.php', 3]]);
});

it('reports {!! !!} of a value, JSON without JSON_HEX_TAG as low, and skips safe output', function () {
    $blade = "{!! \$user->bio !!}\n{!! json_encode(\$data) !!}\n{!! json_encode(\$data, JSON_HEX_TAG) !!}\n{!! csrf_field() !!}\n{!! file_get_contents(resource_path('js/a.js')) !!}\n";
    expect(check(Code\UnescapedBlade::class, ['resources/views/a.blade.php' => $blade]))
        ->toBe([['medium', 'resources/views/a.blade.php', 1], ['low', 'resources/views/a.blade.php', 2]]);
});

it('reports $guarded = [] as low, and the whole request into a model or unguard() as medium', function () {
    $files = ['app/Models/Post.php' => "<?php\nclass Post { protected \$guarded = []; }\n",
        'app/Http/C.php' => "<?php\nPost::create(\$request->all());\nModel::unguard();\nPost::create(\$request->validated());\n"];
    expect(severities(check(Code\MassAssignment::class, $files)))->toBe(['low', 'medium', 'medium']);
});

it('reports state-changing routes without auth by risk, and skips guarded, public and framework routes', function () {
    Route::post('admin/users/delete', fn () => 1);
    Route::post('dev-login/{user}', fn () => 1);
    Route::post('contact', fn () => 1);
    Route::post('settings', fn () => 1)->middleware('auth');
    Route::post('login', fn () => 1);
    Route::put('storage/{path}', fn () => 1);
    Route::get('home', fn () => 1);
    $found = check(Code\UnprotectedRoutes::class);
    expect(severities($found))->toBe(['medium', 'high', 'low']);
});

it('lists CSRF exceptions, a wildcard as medium', function () {
    $app = "<?php\n\$middleware->validateCsrfTokens(except: [\n    'stripe/webhook',\n    'api/*',\n]);\n";
    expect(severities(check(Code\CsrfExceptions::class, ['bootstrap/app.php' => $app])))->toBe(['low', 'medium']);
});

it('reports a POST /login with no rate limit, and accepts throttle or RateLimiter', function () {
    Route::post('login', fn () => 1);
    expect(severities(check(Code\LoginThrottle::class)))->toBe(['medium']);
    expect(check(Code\LoginThrottle::class, ['app/Http/Requests/LoginRequest.php' => "<?php\n\$this->ensureIsNotRateLimited();\n"]))->toBe([]);
});

it('reports a stored upload in a file with no type rule', function () {
    $bad = "<?php\n\$path = \$request->file('a')->store('uploads');\n";
    $good = "<?php\n\$request->validate(['a' => 'mimes:pdf']);\n\$path = \$request->file('a')->store('uploads');\n";
    expect(severities(check(Code\UnvalidatedUploads::class, ['app/A.php' => $bad])))->toBe(['low']);
    expect(check(Code\UnvalidatedUploads::class, ['app/A.php' => $good]))->toBe([]);
});

it('reports a POST form without @csrf, and skips Livewire and Alpine forms', function () {
    $blade = "<form method=\"POST\" action=\"/a\">\n<input name=\"x\">\n</form>\n<form method=\"POST\" action=\"/b\">\n@csrf\n</form>\n<form method=\"POST\" wire:submit=\"save\">\n</form>\n";
    expect(check(Code\FormsWithoutCsrf::class, ['resources/views/f.blade.php' => $blade]))->toBe([['medium', 'resources/views/f.blade.php', 1]]);
});

it('reports env() outside config/', function () {
    expect(severities(check(Code\EnvOutsideConfig::class, ['app/A.php' => "<?php\n\$k = env('API_KEY');\n\$c = config('services.key');\n"])))->toBe(['low']);
});

it('reports a live secret in the code', function () {
    expect(severities(check(Code\SecretsInCode::class, ['config/services.php' => "<?php\nreturn ['stripe' => 'sk_live_".str_repeat('a1', 12)."'];\n"])))->toBe(['high']);
    expect(check(Code\SecretsInCode::class, ['config/services.php' => "<?php\nreturn ['stripe' => env('STRIPE_SECRET')];\n"]))->toBe([]);
});

it('reports an upload stored under the browser\'s file name', function () {
    expect(severities(check(Code\ClientFileName::class, ['app/A.php' => "<?php\n\$f->storeAs('docs', \$f->getClientOriginalName());\n"])))->toBe(['medium']);
});
