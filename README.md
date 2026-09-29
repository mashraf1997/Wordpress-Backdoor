# wp-backdoor-scan

**A defensive scanner that finds PHP backdoors and webshells** in a WordPress install (or any PHP codebase). It reads your files and flags the code patterns and filenames that backdoors use — it never executes or modifies anything.

> This repository previously hosted live webshell code. That material has been removed and the project repurposed into a detection tool for defenders. If you are cleaning up a hacked WordPress site, this is a starting point for triage.

## Usage

```bash
php wp-backdoor-scan.php /path/to/wordpress
```

Example output:

```text
wp-backdoor-scan
────────────────────────────────────────────────────────────────
Scanned 4213 file(s) under /var/www/html

 [CRITICAL] wp-content/uploads/2024/07/logo.php:1
            Executes code coming from request input (eval/assert on $_GET/$_POST/...)  (eval-request-input)
 [HIGH    ] wp-includes/class-wp.php:88
            Writes request input to a file (dropper)  (write-request-to-file)
 [MEDIUM  ] wp-content/mu-plugins/up.php
            Filename commonly used by shells/backdoors  (suspicious-filename)

────────────────────────────────────────────────────────────────
3 finding(s): 1 critical, 1 high, 1 medium
```

### Options

| Option | Description |
| :--- | :--- |
| `--json` | Output findings as JSON (for dashboards or CI) |
| `--min=LEVEL` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` (default `low`) |
| `--ext=LIST` | Extensions to scan (default `php,php3,php4,php5,phtml,pht,phar,inc`) |
| `--max-size=BYTES` | Skip files larger than this (default 3 MB) |
| `-h`, `--help` | Show help |

**Exit codes:** `0` = nothing found at/above the threshold, `1` = findings, `2` = usage error. This makes it usable as a CI gate:

```bash
php wp-backdoor-scan.php --min=high --json public_html/ || echo "Potential backdoor detected!"
```

## What it detects

- **Code execution from request input** — `eval`/`assert`/`system`/`exec`/backticks driven by `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`.
- **Obfuscated payloads** — `eval(base64_decode(...))`, stacked `gzinflate`/`str_rot13` decoders, `preg_replace` with the `/e` modifier, `create_function`, dynamic `$_GET[...]()` calls.
- **Known shell fingerprints** — b374k, c99, r57, WSO, FilesMan and similar signatures.
- **Droppers & uploaders** — writing request input to files, `move_uploaded_file`, hard-coded password gates.
- **Suspicious files** — shell-like filenames and double extensions (`image.php.jpg`, `file.jpg.php`).

## Requirements

- PHP 7.4 or newer (CLI). No external dependencies.

## Limitations

This is a **triage aid**, not a guarantee. Signature/heuristic scanners miss novel or heavily obfuscated backdoors and can flag legitimate code (e.g. a real upload handler). Always:

- Compare files against known-good copies of WordPress core, your theme, and plugins.
- Review anything the scanner flags **and** anything recently modified.
- Rotate credentials and keys after any confirmed compromise.

## License

[GPL-3.0](./LICENSE.txt)
