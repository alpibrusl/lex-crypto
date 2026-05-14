# AGENTS.md — lex-crypto

This file is for AI assistants working in this repo. Read this **first**, then the upstream `docs/AGENT.md` in [alpibrusl/lex-lang](https://github.com/alpibrusl/lex-lang).

## Project layout

```
src/
  util.lex       — shared byte/hex helpers (used by other modules)
  base32.lex     — RFC 4648 Base32 encode/decode
  jwt.lex        — JWT HS256/HS512 sign + verify
  oauth2.lex     — RFC 7636 PKCE helpers for OAuth2
  password.lex   — Argon2id, PBKDF2-SHA256, HKDF-SHA256
  cookie.lex     — signed HMAC + sealed ChaCha20-Poly1305 cookies
  signing.lex    — webhook signature verification (GitHub, Stripe, Slack)
  totp.lex       — RFC 6238 TOTP with SHA-256/512
  main.lex       — package entry point

tests/
  test_util.lex
  test_base32.lex
  test_jwt.lex
  test_password.lex
  test_cookie.lex
  test_signing.lex
  test_totp.lex
  test_oauth2.lex
  test_main.lex
```

## Iteration loop

```sh
lex check src/main.lex     # type-check entry point
lex test                   # run all tests/test_*.lex
lex fmt src/ tests/        # format
lex ci                     # full pipeline (same as CI)
```

## Key conventions

### Tests return Int

`run_all()` returns `Int` (0 = all passed, >0 = failure count). Each test
function returns the number of failed assertions:

```lex
fn chk(cond :: Bool) -> Int {
  if cond { 0 } else { 1 }
}

fn test_foo() -> Int {
  chk(1 + 1 == 2) + chk("a" != "b")
}

fn run_all() -> Int {
  test_foo()
}
```

### No `assert` builtin

The Lex test runner does not provide `assert`. Use `chk` as above, or
`import "std.test" as test` for `test.assert_true / assert_eq / assert_ne /
assert_false` (each returns `Result[Unit, Str]`).

### Module-qualified constructors in patterns

Lex does **not** support module-qualified names in pattern position:

```lex
# WRONG — parse error
match r { Err(jwt.InvalidFormat) => ... }

# CORRECT — bare constructor; type checker infers from context
match r { Err(InvalidFormat) => ... }
```

### Module-qualified constructors in expressions

Lex does **not** support module-qualified constructors in expression
position either (e.g. `totp.TotpSha256` fails). Export a helper function:

```lex
# In src/totp.lex
fn algo_sha256() -> TotpAlgo { TotpSha256 }
```

Then call `totp.algo_sha256()` from tests and user code.

### Entropy is explicit

This library deliberately has **no** `[random]`-effect functions. The caller
supplies entropy via `crypto.random(N)`:

```lex
let verifier := oauth2.pkce_verifier(crypto.random(32))
let salt     := crypto.random(16)
let stored  <- password.hash_argon2id(plain_pw, salt)
let raw     <- cookie.seal_raw(key, value, crypto.random(12), time.now())
```

This keeps all library functions pure and testable under `lex test` (which
blocks `[random]` effects by policy).

### `[time]` effects

JWT verify, cookie verify, Stripe/Slack webhook verify, and TOTP `generate`
all use `time.now()`. Pin the clock in tests:

```sh
LEX_TEST_NOW=1700000000 lex test
```
