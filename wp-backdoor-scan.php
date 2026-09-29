<?php
/**
 * wp-backdoor-scan — a defensive scanner for PHP backdoors and webshells.
 *
 * Recursively scans a directory (e.g. a WordPress install) for the code
 * patterns and file signatures that backdoors and webshells use, then prints a
 * severity-ranked report. It is read-only: it never executes or modifies the
 * files it inspects.
 *
 * Usage:
 *   php wp-backdoor-scan.php [options] <path>
 *
 * Options:
 *   --json           Output findings as JSON
 *   --min=LEVEL      Only report findings at or above LEVEL
 *                    (info|low|medium|high|critical; default: low)
 *   --ext=LIST       Comma-separated extensions to scan
 *                    (default: php,php3,php4,php5,phtml,pht,phar,inc)
 *   --max-size=BYTES Skip files larger than this (default: 3000000)
 *   -h, --help       Show this help
 *
 * Exit codes: 0 = nothing at/above the threshold, 1 = findings, 2 = usage error.
 *
 * @package mashraf1997/wordpress-backdoor
 * @license MIT
 */

error_reporting(E_ALL & ~E_DEPRECATED);

const LEVELS = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

/**
 * Detection rules. Each rule: id, level, description, and either a `regex`
 * (matched against file contents) or a `filename` regex (matched against the
 * path). Regexes are deliberately conservative to limit false positives; this
 * is a triage aid, not a substitute for a full malware audit.
 */
function rules(): array
{
    return [
        // --- Code execution from request input (highest signal) ---
        [
            'id' => 'eval-request-input',
            'level' => 'critical',
            'desc' => 'Executes code coming from request input (eval/assert on $_GET/$_POST/$_REQUEST/$_COOKIE)',
            'regex' => '/\b(?:eval|assert)\s*\(\s*.{0,40}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/is',
        ],
        [
            'id' => 'system-request-input',
            'level' => 'critical',
            'desc' => 'Runs shell commands from request input (system/exec/shell_exec/passthru/popen/proc_open on superglobals)',
            'regex' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*.{0,60}\$_(?:GET|POST|REQUEST|COOKIE)/is',
        ],
        [
            'id' => 'backtick-request-input',
            'level' => 'critical',
            'desc' => 'Shell execution via backticks on request input',
            'regex' => '/`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)[^`]*`/s',
        ],
        // --- Obfuscation / decode-then-execute ---
        [
            'id' => 'eval-base64-decode',
            'level' => 'critical',
            'desc' => 'eval() of decoded/decompressed data — classic packed webshell',
            'regex' => '/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(/is',
        ],
        [
            'id' => 'nested-decoders',
            'level' => 'high',
            'desc' => 'Stacked decoders (gzinflate/base64_decode/str_rot13) — payload obfuscation',
            'regex' => '/(?:gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\(/is',
        ],
        [
            'id' => 'preg-replace-eval',
            'level' => 'critical',
            'desc' => 'preg_replace with the /e modifier — executes the replacement as PHP',
            'regex' => '/preg_replace\s*\(\s*([\'"]).*?\1\s*\.?\s*[\'"]?e[\'"]?/is',
        ],
        [
            'id' => 'variable-function-request',
            'level' => 'high',
            'desc' => 'Dynamic function call driven by request input ($_GET[..](..))',
            'regex' => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/s',
        ],
        [
            'id' => 'create-function',
            'level' => 'medium',
            'desc' => 'create_function() — deprecated dynamic code creation, common in shells',
            'regex' => '/\bcreate_function\s*\(/i',
        ],
        [
            'id' => 'callback-code-exec',
            'level' => 'medium',
            'desc' => 'Code execution through callbacks (call_user_func / array_map / assert with dynamic input)',
            'regex' => '/\b(?:call_user_func(?:_array)?|array_map|array_filter|register_shutdown_function)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/is',
        ],
        // --- Long opaque blobs ---
        [
            'id' => 'long-base64-blob',
            'level' => 'medium',
            'desc' => 'Very long base64-like string (>1500 chars) — often an embedded payload',
            'regex' => '/[A-Za-z0-9+\/]{1500,}={0,2}/',
        ],
        // --- Known shell fingerprints ---
        [
            'id' => 'known-shell-signature',
            'level' => 'critical',
            'desc' => 'Signature string of a known webshell (b374k, c99, r57, WSO, FilesMan, etc.)',
            'regex' => '/\b(?:b374k|c99shell|r57shell|WSO(?:\s|_)?[0-9.]*shell|FilesMan|Sh3ll|priv8|IndoXploit|MADSPOT|"?wso"?\s*shell)\b/i',
        ],
        [
            'id' => 'password-protected-shell',
            'level' => 'high',
            'desc' => 'Hard-coded password gate combined with request handling — typical shell auth',
            'regex' => '/\$(?:pass|password|auth|key)\s*=\s*[\'"][0-9a-f]{16,}[\'"]/i',
        ],
        // --- File drop / upload primitives ---
        [
            'id' => 'write-request-to-file',
            'level' => 'high',
            'desc' => 'Writes request input to a file (fwrite/file_put_contents of a superglobal) — dropper',
            'regex' => '/\b(?:file_put_contents|fwrite|fputs)\s*\([^;]*\$_(?:GET|POST|REQUEST|FILES|COOKIE)/is',
        ],
        [
            'id' => 'move-uploaded-file',
            'level' => 'low',
            'desc' => 'Handles file uploads (move_uploaded_file) — verify it validates type and destination',
            'regex' => '/\bmove_uploaded_file\s*\(/i',
        ],
        // --- Suspicious filenames ---
        [
            'id' => 'suspicious-filename',
            'level' => 'medium',
            'desc' => 'Filename commonly used by shells/backdoors',
            'filename' => '/(?:^|\/)(?:shell|c99|r57|wso|b374k|backdoor|webshell|cmd|adminer|logmein|mirror|up|upload|by|xleet|alfa|priv8)\b[^\/]*\.(?:php|phtml|pht|phar)$/i',
        ],
        [
            'id' => 'double-extension',
            'level' => 'medium',
            'desc' => 'Double extension hiding a PHP file (e.g. image.php.jpg or file.jpg.php)',
            'filename' => '/\.(?:php|phtml|pht|phar)\.(?:jpg|jpeg|png|gif|txt|ico)$|\.(?:jpg|jpeg|png|gif)\.(?:php|phtml|pht|phar)$/i',
        ],
    ];
}

function parse_args(array $argv): array
{
    $opts = ['json' => false, 'min' => 'low', 'ext' => 'php,php3,php4,php5,phtml,pht,phar,inc', 'max-size' => 3000000, 'path' => null];
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '-h' || $arg === '--help') {
            $opts['help'] = true;
        } elseif ($arg === '--json') {
            $opts['json'] = true;
        } elseif (preg_match('/^--min=(.+)$/', $arg, $m)) {
            $opts['min'] = strtolower($m[1]);
        } elseif (preg_match('/^--ext=(.+)$/', $arg, $m)) {
            $opts['ext'] = $m[1];
        } elseif (preg_match('/^--max-size=(\d+)$/', $arg, $m)) {
            $opts['max-size'] = (int) $m[1];
        } elseif ($arg[0] !== '-') {
            $opts['path'] = $arg;
        }
    }
    return $opts;
}

function usage(): void
{
    fwrite(STDERR, <<<TXT
wp-backdoor-scan — detect PHP backdoors and webshells (read-only).

Usage: php wp-backdoor-scan.php [options] <path>

  --json            Output findings as JSON
  --min=LEVEL       Minimum severity to report (info|low|medium|high|critical; default: low)
  --ext=LIST        Extensions to scan (default: php,php3,php4,php5,phtml,pht,phar,inc)
  --max-size=BYTES  Skip files larger than this (default: 3000000)
  -h, --help        Show this help

Exit codes: 0 = clean, 1 = findings at/above the threshold, 2 = usage error.

TXT);
}

/**
 * @return array{0: int, 1: int} [line number, 1-indexed] and column for an offset.
 */
function line_of(string $content, int $offset): int
{
    return substr_count($content, "\n", 0, min($offset, strlen($content))) + 1;
}

$opts = parse_args($argv);
if (!empty($opts['help'])) {
    usage();
    exit(0);
}
if ($opts['path'] === null) {
    usage();
    exit(2);
}
if (!is_dir($opts['path']) && !is_file($opts['path'])) {
    fwrite(STDERR, "Path not found: {$opts['path']}\n");
    exit(2);
}
if (!isset(LEVELS[$opts['min']])) {
    fwrite(STDERR, "Invalid --min level: {$opts['min']}\n");
    exit(2);
}

$minLevel = LEVELS[$opts['min']];
$extensions = array_filter(array_map('trim', explode(',', strtolower($opts['ext']))));
$rules = rules();

// Collect the files to scan.
$files = [];
if (is_file($opts['path'])) {
    $files[] = $opts['path'];
} else {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($opts['path'], FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($it as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $ext = strtolower($file->getExtension());
        if (in_array($ext, $extensions, true)) {
            $files[] = $file->getPathname();
        }
    }
}
sort($files);

$findings = [];
$scanned = 0;
foreach ($files as $path) {
    if (filesize($path) > $opts['max-size']) {
        continue;
    }
    $content = @file_get_contents($path);
    if ($content === false) {
        continue;
    }
    $scanned++;
    foreach ($rules as $rule) {
        if (isset($rule['filename'])) {
            if (preg_match($rule['filename'], str_replace('\\', '/', $path))) {
                $findings[] = ['file' => $path, 'line' => 0, 'rule' => $rule['id'], 'level' => $rule['level'], 'desc' => $rule['desc']];
            }
            continue;
        }
        if (preg_match($rule['regex'], $content, $m, PREG_OFFSET_CAPTURE)) {
            $findings[] = [
                'file' => $path,
                'line' => line_of($content, $m[0][1]),
                'rule' => $rule['id'],
                'level' => $rule['level'],
                'desc' => $rule['desc'],
            ];
        }
    }
}

// Filter by threshold and sort most-severe first.
$findings = array_values(array_filter($findings, fn ($f) => LEVELS[$f['level']] >= $minLevel));
usort($findings, fn ($a, $b) => LEVELS[$b['level']] <=> LEVELS[$a['level']] ?: strcmp($a['file'], $b['file']));

if ($opts['json']) {
    echo json_encode([
        'scanned_files' => $scanned,
        'findings' => $findings,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit($findings ? 1 : 0);
}

$colors = ['critical' => "\033[41;97m", 'high' => "\033[31m", 'medium' => "\033[33m", 'low' => "\033[36m", 'info' => "\033[2m"];
$useColor = function_exists('posix_isatty') ? @posix_isatty(STDOUT) : getenv('NO_COLOR') === false;
$paint = function (string $level, string $s) use ($colors, $useColor) {
    return $useColor ? ($colors[$level] ?? '') . $s . "\033[0m" : $s;
};

echo "wp-backdoor-scan\n";
echo str_repeat('─', 64) . "\n";
echo "Scanned {$scanned} file(s) under {$opts['path']}\n\n";

if (!$findings) {
    echo $paint('low', "✔ No suspicious patterns found at or above '{$opts['min']}'.") . "\n";
    echo "Note: a clean result is not a guarantee. Review new or modified files by hand too.\n";
    exit(0);
}

foreach ($findings as $f) {
    $loc = $f['line'] > 0 ? "{$f['file']}:{$f['line']}" : $f['file'];
    echo $paint($f['level'], sprintf(' [%-8s]', strtoupper($f['level']))) . " {$loc}\n";
    echo "            {$f['desc']}  ({$f['rule']})\n";
}

$counts = array_count_values(array_column($findings, 'level'));
echo "\n" . str_repeat('─', 64) . "\n";
$summary = [];
foreach (['critical', 'high', 'medium', 'low', 'info'] as $lvl) {
    if (!empty($counts[$lvl])) {
        $summary[] = $paint($lvl, "{$counts[$lvl]} {$lvl}");
    }
}
echo count($findings) . ' finding(s): ' . implode(', ', $summary) . "\n";
echo "Investigate each file; confirm it belongs in your site before deleting.\n";
exit(1);
