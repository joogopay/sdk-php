<?php

declare(strict_types=1);

/**
 * Every public class must be reachable through composer.json's autoload rules.
 * The other tests require source files directly, so a class that PSR-4 cannot
 * find still passes them and only fails once a merchant installs the package.
 */

$root = dirname(__DIR__);
$config = json_decode((string) file_get_contents($root . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
$psr4 = $config['autoload']['psr-4'] ?? [];
$classmap = $config['autoload']['classmap'] ?? [];

$declared = [];
foreach (glob($root . '/src/*.php') as $file) {
    $source = (string) file_get_contents($file);
    preg_match('/^namespace\s+([^;]+);/m', $source, $ns);
    preg_match_all('/^(?:final\s+|abstract\s+)?class\s+(\w+)/m', $source, $classes);
    foreach ($classes[1] as $class) {
        $declared[trim($ns[1]) . '\\' . $class] = $file;
    }
}

$classmapFiles = array_map(static fn (string $p): string => $root . '/' . $p, $classmap);
$unreachable = [];
foreach ($declared as $class => $file) {
    if (in_array($file, $classmapFiles, true)) {
        continue;
    }
    $found = false;
    foreach ($psr4 as $prefix => $dir) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }
        $relative = str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if ($root . '/' . rtrim($dir, '/') . '/' . $relative === $file) {
            $found = true;
            break;
        }
    }
    if (!$found) {
        $unreachable[] = $class . ' (' . basename($file) . ')';
    }
}

if ($unreachable !== []) {
    fwrite(STDERR, "FAIL: classes composer cannot autoload:\n  " . implode("\n  ", $unreachable) . "\n");
    fwrite(STDERR, "Add the file to autoload.classmap in composer.json, or split it so each class has its own file.\n");
    exit(1);
}

printf("  ok: all %d public classes are reachable through composer autoload\n", count($declared));
