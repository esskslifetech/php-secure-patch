<?php
/**
 * protection2shell :: project-scanner.php
 * Deep PHP project/framework detection — complements the bash detection in
 * setup.sh with composer-aware analysis.  Runs on PHP >= 5.6.
 *
 *   php scanner/project-scanner.php --path /var/www --json report.json
 *   php scanner/project-scanner.php --path /var/www --path /srv --depth 5
 *
 * Exit codes: 0 = scan completed, 1 = usage error.
 */

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "cli only\n");
    exit(1);
}

$opts = getopt('', array('path:', 'json:', 'depth:', 'help'));
if (isset($opts['help'])) {
    echo "Usage: php project-scanner.php --path DIR [--path DIR...] [--json FILE] [--depth N]\n";
    exit(0);
}
$paths = isset($opts['path']) ? (array)$opts['path'] : array('/var/www', '/srv', '/home');
$depth = isset($opts['depth']) ? (int)$opts['depth'] : 4;
$jsonOut = isset($opts['json']) ? $opts['json'] : null;

/** framework marker definitions: [relative path, regex on file, label] */
$markers = array(
    array('wp-load.php', null, 'wordpress'),
    array('core/lib/Drupal.php', "/const VERSION = '([^']+)'/", 'drupal'),
    array('configuration.php', null, 'joomla'),
    array('version.php', '/\$release\s*=\s*.([0-9][0-9.a-z]*)/', 'moodle'),
    array('includes/Defines.php', "/define\(\s*'MW_VERSION',\s*'([^']+)'/", 'mediawiki'),
    array('includes/constants.php', "/PHPBB_VERSION',\s*'([^']+)'/", 'phpbb'),
    array('artisan', null, 'artisan-cli'),
    array('composer.json', null, 'composer'),
);

/** composer require keys -> framework label */
$composerMap = array(
    'laravel/framework' => 'laravel',
    'symfony/symfony' => 'symfony',
    'symfony/http-kernel' => 'symfony',
    'drupal/core' => 'drupal',
    'yiisoft/yii2' => 'yii',
    'cakephp/cakephp' => 'cakephp',
    'codeigniter4/framework' => 'codeigniter',
    'magento/product-community-edition' => 'magento',
    'magento/product-enterprise-edition' => 'magento',
    'shopware/shopware' => 'shopware',
    'phpmyadmin/phpmyadmin' => 'phpmyadmin',
    'nextcloud/server' => 'nextcloud',
    'typo3/cms' => 'typo3',
    'silverstripe/silverstripe-framework' => 'silverstripe',
    'craftcms/cms' => 'craft',
    'prestashop/prestashop' => 'prestashop',
    'vanilla/vanilla' => 'vanilla',
    'piwik/piwik' => 'matomo',
    'matomo/matomo' => 'matomo',
);

function find_upward($start, $depth)
{
    // collect candidate project roots: any dir within $depth containing markers
    $roots = array();
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($start, FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    $skip = array('vendor', 'node_modules', '.git', '.svn', 'cache', 'tmp', 'tests', 'test');
    $base = realpath($start);
    foreach ($it as $file) {
        if ($it->getDepth() > $depth) {
            continue;
        }
        if (!$file->isFile()) {
            continue;
        }
        $name = $file->getFilename();
        if ($name === 'wp-load.php' || $name === 'composer.json' || $name === 'configuration.php'
            || $name === 'artisan' || $name === 'version.php' || $name === 'Defines.php') {
            $dir = $file->getPath();
            // skip-list must match whole path SEGMENTS below the scan root only
            // (so scanning /tmp still works, but /var/www/site/vendor is skipped)
            $rel = ($base !== false && strpos($dir, $base . DIRECTORY_SEPARATOR) === 0)
                ? substr($dir, strlen($base) + 1) : $dir;
            $segments = ($rel === '' || $rel === false) ? array() : explode(DIRECTORY_SEPARATOR, $rel);
            $skipThis = false;
            foreach ($segments as $seg) {
                if (in_array($seg, $skip, true)) {
                    $skipThis = true;
                    break;
                }
            }
            if ($skipThis) {
                continue;
            }
            $roots[$dir] = true;
        }
    }
    return array_keys($roots);
}

function read_first_match($file, $regex)
{
    if ($regex === null) {
        return null;
    }
    $data = @file_get_contents($file);
    if ($data === false) {
        return null;
    }
    if (preg_match($regex, $data, $m)) {
        return isset($m[1]) ? $m[1] : true;
    }
    return null;
}

function composer_pkg_version($lockFile, $pkg)
{
    $data = @file_get_contents($lockFile);
    if ($data === false) {
        return null;
    }
    $lock = json_decode($data, true);
    if (!is_array($lock)) {
        return null;
    }
    foreach (array('packages', 'packages-dev') as $section) {
        if (!isset($lock[$section]) || !is_array($lock[$section])) {
            continue;
        }
        foreach ($lock[$section] as $p) {
            if (isset($p['name'], $p['version']) && $p['name'] === $pkg) {
                return $p['version'];
            }
        }
    }
    return null;
}

function scan_root($root)
{
    global $markers, $composerMap, $depth;
    $projects = array();

    // realpath so the output is clean
    $root = realpath($root);
    if ($root === false) {
        return $projects;
    }

    // fast single-dir check first (the root itself may be a project)
    foreach (find_upward($root, $depth) as $dir) {
        $proj = array('path' => $dir, 'type' => 'generic-php', 'version' => null, 'php_constraint' => null, 'packages' => array());

        foreach ($markers as $mk) {
            $f = $dir . DIRECTORY_SEPARATOR . $mk[0];
            if (file_exists($f)) {
                if ($mk[2] === 'wordpress' && file_exists($dir . '/wp-includes/version.php')) {
                    $v = read_first_match($dir . '/wp-includes/version.php', '/\$wp_version\s*=\s*.([0-9.a-z]+)./');
                    $proj['type'] = 'wordpress';
                    $proj['version'] = $v;
                } elseif ($mk[2] === 'moodle' && file_exists($dir . '/config.php')) {
                    $proj['type'] = 'moodle';
                    $proj['version'] = read_first_match($f, $mk[1]);
                } elseif ($mk[2] === 'joomla' && (file_exists($dir . '/libraries/src/Version.php') || file_exists($dir . '/administrator/manifests/files/joomla.xml'))) {
                    $proj['type'] = 'joomla';
                    $v = read_first_match($dir . '/libraries/src/Version.php', '/MAJOR_VERSION = ([0-9]+);/');
                    $proj['version'] = $v;
                } elseif ($mk[2] !== 'composer' && $mk[2] !== 'artisan-cli') {
                    $proj['type'] = $mk[2];
                    $proj['version'] = read_first_match($f, $mk[1]);
                }
            }
        }

        // composer-aware
        $cj = $dir . '/composer.json';
        if (file_exists($cj)) {
            $meta = json_decode(@file_get_contents($cj), true);
            if (is_array($meta)) {
                if (isset($meta['require']['php'])) {
                    $proj['php_constraint'] = $meta['require']['php'];
                }
                $reqs = array_merge(
                    isset($meta['require']) ? $meta['require'] : array(),
                    isset($meta['require-dev']) ? $meta['require-dev'] : array()
                );
                foreach ($composerMap as $pkg => $label) {
                    if (isset($reqs[$pkg])) {
                        $proj['type'] = $label;
                        $proj['packages'][$pkg] = isset($reqs[$pkg]) ? $reqs[$pkg] : '*';
                        $lv = composer_pkg_version($dir . '/composer.lock', $pkg);
                        if ($lv !== null) {
                            $proj['version'] = $lv;
                        }
                        break;
                    }
                }
            }
        }

        // skip duplicate (e.g. wordpress root also containing composer.json scanned twice)
        $projects[$dir] = $proj;
    }
    return array_values($projects);
}

$all = array();
foreach ($paths as $p) {
    if (!is_dir($p)) {
        fwrite(STDERR, "[warn] not a directory: $p\n");
        continue;
    }
    foreach (scan_root($p) as $proj) {
        $all[$proj['path']] = $proj;
    }
}
$all = array_values($all);

if ($jsonOut !== null) {
    file_put_contents($jsonOut, json_encode(array('generated_at' => gmdate('c'), 'projects' => $all), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    fwrite(STDERR, "[ OK ] wrote $jsonOut\n");
}

// human table
printf("%-14s %-48s %-12s %s\n", 'TYPE', 'PATH', 'VERSION', 'PHP-REQ');
printf("%s\n", str_repeat('-', 96));
foreach ($all as $p) {
    printf("%-14s %-48s %-12s %s\n",
        substr((string)$p['type'], 0, 14),
        substr($p['path'], 0, 48),
        substr((string)(isset($p['version']) ? $p['version'] : '-'), 0, 12),
        isset($p['php_constraint']) ? $p['php_constraint'] : '-'
    );
}
printf("\n%d project(s) scanned.\n", count($all));
exit(0);
