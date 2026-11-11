<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

/**
 * Autoloader for the Logihertz\JsonlLogger namespace.
 *
 * Implements a lightweight, zero-dependency PSR-4 autoloader strictly
 * mapping the `Logihertz\JsonlLogger\` namespace to the `src/` directory.
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class Autoloader
{
    public const PREFIX = 'Logihertz\\JsonlLogger\\';

    /**
     * Register the PSR-4 autoloader with SPL.
     */
    public static function register(): void
    {
        spl_autoload_register(static function (string $class): void {
            if (!str_starts_with($class, self::PREFIX)) {
                return;
            }

            $relative = substr($class, strlen(self::PREFIX));
            $file = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';

            if (is_file($file)) {
                require_once $file;
            }
        });
    }
}
