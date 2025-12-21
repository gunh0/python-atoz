# security — secure coding with the Python standard library

My notes on writing Python that handles untrusted input and secrets, organised by CWE. Each example runs the vulnerable version next to the fix, so the output shows the bug actually happening (harmlessly) before showing why the fix holds.

Crypto examples are checked against RFC test vectors where they exist (HMAC RFC 4231, HKDF RFC 5869, PBKDF2 RFC 6070, scrypt RFC 7914).

```bash
python3 security/<topic>/<example>.py      # every example runs on its own
python3 scripts/check.py security          # run all and compare with the # Output: blocks
```

37 examples, checked on Python 3.13, Python 3.14.

## injection

Commands, arguments, SQL, eval, templates, logs and CSV exports.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-78 | [`cwe78_os_command_injection.py`](injection/cwe78_os_command_injection.py) | OS command injection — build argument lists, never shell strings |
| CWE-78 | [`cwe78_shlex_quote.py`](injection/cwe78_shlex_quote.py) | when a shell string is unavoidable, quote with shlex.quote |
| CWE-88 | [`cwe88_argument_injection.py`](injection/cwe88_argument_injection.py) | argument injection — a file name that starts with "-" is an option |
| CWE-89 | [`cwe89_dynamic_identifiers.py`](injection/cwe89_dynamic_identifiers.py) | ORDER BY and other identifiers cannot be bound — allow-list them |
| CWE-89 | [`cwe89_sql_injection.py`](injection/cwe89_sql_injection.py) | SQL injection — bind values with placeholders, never format them in |
| CWE-95 | [`cwe95_eval_sandbox_escape.py`](injection/cwe95_eval_sandbox_escape.py) | eval() with empty __builtins__ is not a sandbox |
| CWE-95 | [`cwe95_eval_vs_literal_eval.py`](injection/cwe95_eval_vs_literal_eval.py) | eval injection — parse data with ast.literal_eval or json, never eval |
| CWE-1336 | [`format_string_injection.py`](injection/format_string_injection.py) | template injection with str.format — attribute traversal leaks secrets |
| CWE-79/CWE-78 | [`tstring_html_shell.py`](injection/tstring_html_shell.py) | CWE-79 / CWE-78 with PEP 750 template strings: render HTML and argv safely |
| CWE-89 | [`tstring_safe_sql.py`](injection/tstring_safe_sql.py) | CWE-89 with PEP 750 template strings: t"..." keeps values out of the SQL text |

## files

Paths, symlinks, temp files, races, permissions, and zip/tar extraction.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-22 | [`cwe22_path_traversal.py`](files/cwe22_path_traversal.py) | path traversal — resolve the path, then check it is inside the base |
| CWE-367 | [`cwe367_toctou_open_flags.py`](files/cwe367_toctou_open_flags.py) | TOCTOU — check the file you opened, not the name you checked |
| CWE-377 | [`cwe377_insecure_temp_file.py`](files/cwe377_insecure_temp_file.py) | insecure temporary file — mktemp() hands out a name, not a file |
| CWE-59 | [`cwe59_symlink_following.py`](files/cwe59_symlink_following.py) | link following — open() happily writes through an attacker's symlink |
| CWE-59/CWE-22 | [`tar_links_and_filters.py`](files/tar_links_and_filters.py) | Tar slip via links (CWE-59/CWE-22): what each extraction filter allows |
| CWE-22 | [`tar_slip_extraction_filter.py`](files/tar_slip_extraction_filter.py) | Tar slip (CWE-22): pass filter="data" to every tarfile extraction |
| — | [`tarfile_default_filter_314.py`](files/tarfile_default_filter_314.py) | Python 3.14: tarfile extracts with filter="data" by default |
| CWE-22 | [`zip_slip.py`](files/zip_slip.py) | Zip slip (CWE-22): archive member names are untrusted paths |

## web

HTML escaping by context, URL schemes, open redirects, header injection and SSRF.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-79 | [`cwe79_html_escape_context.py`](web/cwe79_html_escape_context.py) | cross-site scripting — escaping depends on where the value lands |
| CWE-79 | [`cwe79_url_scheme_allowlist.py`](web/cwe79_url_scheme_allowlist.py) | user-supplied links — escaping is not enough inside href |

## crypto

Randomness, hashes, MACs and KDFs, constant-time comparison, identifiers and integrity manifests.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-208 | [`constant_time_compare.py`](crypto/constant_time_compare.py) | timing side channel — compare MACs and tokens with hmac.compare_digest |
| CWE-328 | [`hashlib_basics.py`](crypto/hashlib_basics.py) | weak hashes — hashlib basics, usedforsecurity, and digest misuse |
| — | [`hkdf_rfc5869.py`](crypto/hkdf_rfc5869.py) | HKDF from hmac, verified against RFC 5869 — one master key, independent subkeys |
| — | [`hmac_rfc4231.py`](crypto/hmac_rfc4231.py) | HMAC-SHA-256/512 checked against the RFC 4231 test vectors |
| CWE-327 | [`naive_mac_length_extension.py`](crypto/naive_mac_length_extension.py) | sha256(secret + message) is not a MAC — length extension, and why HMAC exists |
| CWE-338 | [`secrets_vs_random.py`](crypto/secrets_vs_random.py) | weak PRNG for security tokens — use secrets, never random |
| CWE-340 | [`uuid7_time_leak.py`](crypto/uuid7_time_leak.py) | uuid.uuid7() (Python 3.14) — great primary key, poor public ID, no token |
| CWE-340 | [`uuid_leaks.py`](crypto/uuid_leaks.py) | predictable identifiers — uuid1 leaks time and MAC, uuid4 does not |

## auth

Password storage, JWT, sessions, CSRF, rate limiting and lockout.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-347 | [`jwt_hs256.py`](auth/jwt_hs256.py) | JWT validation — a signature check alone is not enough |
| CWE-916 | [`password_storage.py`](auth/password_storage.py) | password hashing — salted scrypt/PBKDF2 strings and upgrade-on-login rehash |
| CWE-384 | [`session_tokens.py`](auth/session_tokens.py) | session fixation — rotate the session id at login, store only its hash |

## secrets

Keeping secrets out of logs and `repr`, loading them safely, scanning for them, audit hooks.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-532 | [`log_masking_filter.py`](secrets/log_masking_filter.py) | secrets in logs — redact with a logging.Filter on the handler |
| CWE-532 | [`repr_redaction.py`](secrets/repr_redaction.py) | secrets leaking through repr — redact at the type, not at every call site |
| CWE-798 | [`secret_scanner.py`](secrets/secret_scanner.py) | hard-coded credentials — a secret scanner with regex rules and entropy |
| CWE-532 | [`tstring_log_redaction.py`](secrets/tstring_log_redaction.py) | redact secrets in logs with t-strings (PEP 750, Python 3.14) |

## supply-chain

Pinned hashes, requirement audits, typosquats and resource limits for helpers.

| CWE | Example | Notes |
| --- | --- | --- |
| CWE-494 | [`hash_pinned_downloads.py`](supply-chain/hash_pinned_downloads.py) | download without integrity check — verify against hashes pinned in the lock |
| — | [`typosquat_detector.py`](supply-chain/typosquat_detector.py) | Typosquatting — flag new dependencies one typo away from a popular package |

## CWE index

- [CWE-22](https://cwe.mitre.org/data/definitions/22.html): [`cwe22_path_traversal.py`](files/cwe22_path_traversal.py), [`tar_links_and_filters.py`](files/tar_links_and_filters.py), [`tar_slip_extraction_filter.py`](files/tar_slip_extraction_filter.py), [`zip_slip.py`](files/zip_slip.py)
- [CWE-59](https://cwe.mitre.org/data/definitions/59.html): [`cwe59_symlink_following.py`](files/cwe59_symlink_following.py), [`tar_links_and_filters.py`](files/tar_links_and_filters.py)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): [`cwe78_os_command_injection.py`](injection/cwe78_os_command_injection.py), [`cwe78_shlex_quote.py`](injection/cwe78_shlex_quote.py), [`tstring_html_shell.py`](injection/tstring_html_shell.py)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): [`tstring_html_shell.py`](injection/tstring_html_shell.py), [`cwe79_html_escape_context.py`](web/cwe79_html_escape_context.py), [`cwe79_url_scheme_allowlist.py`](web/cwe79_url_scheme_allowlist.py)
- [CWE-88](https://cwe.mitre.org/data/definitions/88.html): [`cwe88_argument_injection.py`](injection/cwe88_argument_injection.py)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): [`cwe89_dynamic_identifiers.py`](injection/cwe89_dynamic_identifiers.py), [`cwe89_sql_injection.py`](injection/cwe89_sql_injection.py), [`tstring_safe_sql.py`](injection/tstring_safe_sql.py)
- [CWE-95](https://cwe.mitre.org/data/definitions/95.html): [`cwe95_eval_sandbox_escape.py`](injection/cwe95_eval_sandbox_escape.py), [`cwe95_eval_vs_literal_eval.py`](injection/cwe95_eval_vs_literal_eval.py)
- [CWE-208](https://cwe.mitre.org/data/definitions/208.html): [`constant_time_compare.py`](crypto/constant_time_compare.py)
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): [`naive_mac_length_extension.py`](crypto/naive_mac_length_extension.py)
- [CWE-328](https://cwe.mitre.org/data/definitions/328.html): [`hashlib_basics.py`](crypto/hashlib_basics.py)
- [CWE-338](https://cwe.mitre.org/data/definitions/338.html): [`secrets_vs_random.py`](crypto/secrets_vs_random.py)
- [CWE-340](https://cwe.mitre.org/data/definitions/340.html): [`uuid7_time_leak.py`](crypto/uuid7_time_leak.py), [`uuid_leaks.py`](crypto/uuid_leaks.py)
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html): [`jwt_hs256.py`](auth/jwt_hs256.py)
- [CWE-367](https://cwe.mitre.org/data/definitions/367.html): [`cwe367_toctou_open_flags.py`](files/cwe367_toctou_open_flags.py)
- [CWE-377](https://cwe.mitre.org/data/definitions/377.html): [`cwe377_insecure_temp_file.py`](files/cwe377_insecure_temp_file.py)
- [CWE-384](https://cwe.mitre.org/data/definitions/384.html): [`session_tokens.py`](auth/session_tokens.py)
- [CWE-494](https://cwe.mitre.org/data/definitions/494.html): [`hash_pinned_downloads.py`](supply-chain/hash_pinned_downloads.py)
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html): [`log_masking_filter.py`](secrets/log_masking_filter.py), [`repr_redaction.py`](secrets/repr_redaction.py), [`tstring_log_redaction.py`](secrets/tstring_log_redaction.py)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): [`secret_scanner.py`](secrets/secret_scanner.py)
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html): [`password_storage.py`](auth/password_storage.py)
- [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html): [`format_string_injection.py`](injection/format_string_injection.py)
