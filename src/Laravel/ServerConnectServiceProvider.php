<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Laravel;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Kongpda\ServerConnect\Connector;
use Kongpda\ServerConnect\KeyInstaller;
use Kongpda\ServerConnect\Phpseclib\PhpseclibConnector;
use Kongpda\ServerConnect\TargetGuard;

/**
 * Optional Laravel wiring: binds the Connector to phpseclib and builds the
 * TargetGuard from config/server-connect.php. Swap the Connector for
 * Testing\FakeConnector in tests.
 */
final class ServerConnectServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/server-connect.php', 'server-connect');

        $this->app->bind(Connector::class, function (Application $app): Connector {
            $config = $app->make(Repository::class);

            return new PhpseclibConnector(
                (int) $config->get('server-connect.connect_timeout', 8),
                (int) $config->get('server-connect.keepalive', 5),
                (int) $config->get('server-connect.min_rsa_bits', 2048),
                (int) $config->get('server-connect.max_output_bytes', 4 * 1024 * 1024),
            );
        });

        $this->app->bind(TargetGuard::class, function (Application $app): TargetGuard {
            $config = $app->make(Repository::class);
            $appHost = parse_url((string) $config->get('app.url', ''), PHP_URL_HOST);
            /** @var list<string> $own */
            $own = array_values(array_filter([...(array) $config->get('server-connect.own_hosts', []), is_string($appHost) ? $appHost : ''], fn ($host): bool => is_string($host) && $host !== ''));

            return new TargetGuard(
                (bool) $config->get('server-connect.allow_local', false),
                $own,
                allowPrivate: (bool) $config->get('server-connect.allow_private', false),
            );
        });

        $this->app->bind(KeyInstaller::class, fn (Application $app): KeyInstaller => new KeyInstaller($app->make(Connector::class)));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../../config/server-connect.php' => $this->app->configPath('server-connect.php')], 'server-connect-config');
        }
    }
}
