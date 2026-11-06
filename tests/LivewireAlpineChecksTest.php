<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Olgun\SecurityCheck\Checks\Alpine;
use Olgun\SecurityCheck\Checks\Livewire;
use Olgun\SecurityCheck\Tests\Fixtures\Livewire\BillingPage;

function component(string $body): array
{
    return [...LIVEWIRE, 'app/Livewire/Thing.php' => "<?php\nuse Livewire\\Component;\nclass Thing extends Component\n{\n$body\n}\n"];
}

it('skips the Livewire checks in an app without Livewire', function () {
    expect(check(Livewire\ModelOnPublicProperty::class, ['app/A.php' => '<?php']))->toBe('skipped');
});

it('reports the property rules of the livewire-security scanner', function () {
    expect(severities(check(Livewire\ModelOnPublicProperty::class, component('    public Model $post;'))))->toBe(['low']);
    expect(severities(check(Livewire\IdentityPublicProperty::class, component('    public string $email = \'\';'))))->toBe(['low']);
    expect(severities(check(Livewire\PublicPageProps::class, component('    public array $props = [];'))))->toBe(['medium']);
    expect(check(Livewire\PublicPageProps::class, component("    #[Locked]\n    public array \$props = [];")))->toBe([]);
    expect(severities(check(Livewire\UrlWritableIdentifier::class, component("    #[Url]\n    public int \$postId = 0;"))))->toBe(['medium']);
    expect(severities(check(Livewire\UntypedPublicProperty::class, component('    public $title;'))))->toBe(['low']);
});

it('reports an action that writes a record without authorization, and nothing else', function () {
    $unguarded = "    public function deletePost(int \$id): void\n    {\n        Post::findOrFail(\$id)->delete();\n    }";
    $guarded = "    public function deletePost(int \$id): void\n    {\n        \$post = Post::findOrFail(\$id);\n        \$this->authorize('delete', \$post);\n        \$post->delete();\n    }";
    // The helper is above the action, so the action's own 40-line window does not hold the helper's Gate call.
    $helper = "    private function check(int \$id): Post\n    {\n        return Gate::authorize('x') ?? Post::find(\$id);\n    }\n    public function deletePost(int \$id): void\n    {\n        \$post = \$this->check(\$id);\n        \$post->delete();\n    }";
    $stateOnly = "    public function removeStep(int \$i): void\n    {\n        unset(\$this->steps[\$i]);\n    }";
    $hook = "    public function updatedTitle(): void\n    {\n        Post::first()->update(['t' => 1]);\n    }";
    expect(severities(check(Livewire\UnauthorizedMutator::class, component($unguarded))))->toBe(['high']);
    foreach ([$guarded, $helper, $stateOnly, $hook] as $body) {
        expect(check(Livewire\UnauthorizedMutator::class, component($body)))->toBe([]);
    }
});

it('reports a cross-user computed cache with no key', function () {
    expect(severities(check(Livewire\ComputedCacheWithoutKey::class, component("    #[Computed(cache: true)]\n    public function orders() {}"))))->toBe(['high']);
    expect(check(Livewire\ComputedCacheWithoutKey::class, component("    #[Computed(cache: true, key: 'o')]\n    public function orders() {}")))->toBe([]);
});

it('reports a Livewire page behind middleware that the update endpoint does not repeat', function () {
    Route::get('billing', BillingPage::class)->middleware('permission:manage billing');
    Route::get('plain', fn () => 1)->middleware('permission:x');
    expect(severities(check(Livewire\MiddlewareNotRepeated::class, LIVEWIRE)))->toBe(['medium']);
});

it('reports server data in an Alpine expression, as the alpinejs-security reviewer does', function () {
    $blade = implode("\n", [
        '<button @click="buy(\'{{ $sku }}\')">a</button>',
        '<div x-data="{ a: {{ json_encode($a) }} }"></div>',
        '<x-link :href="route(\'a\', \'{{ $id }}\')">a</x-link>',
        '<div x-show="tab === \'{{ $tab }}\'"></div>',
        '<span x-text="title"></span>',
    ]);
    $found = check(Alpine\BladeInAlpineExpression::class, ['resources/views/a.blade.php' => $blade]);
    expect(array_column($found, 2))->toBe([1, 4]);
});

it('reports x-html, a persisted secret and a bound URL', function () {
    expect(severities(check(Alpine\XHtml::class, ['resources/views/a.blade.php' => '<div x-data><p x-html="body"></p></div>'])))->toBe(['medium']);
    expect(severities(check(Alpine\PersistedSecret::class, ['resources/views/a.blade.php' => '<div x-data="{ token: $persist(\'\') }"></div>'])))->toBe(['medium']);
    expect(check(Alpine\PersistedSecret::class, ['resources/views/a.blade.php' => '<div x-data="{ tab: $persist(\'a\') }"></div>']))->toBe([]);
    expect(severities(check(Alpine\UrlBinding::class, ['resources/views/a.blade.php' => '<div x-data><a :href="link">x</a><x-nav :href="$url" /></div>'])))->toBe(['low']);
});
