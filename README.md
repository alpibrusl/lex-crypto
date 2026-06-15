# lex-crypto

[![CI](https://github.com/alpibrusl/lex-crypto/actions/workflows/lex.yml/badge.svg)](https://github.com/alpibrusl/lex-crypto/actions/workflows/lex.yml)

**Part of the [Lex](https://lexlang.org) project** — Library · [Manifesto](https://lexlang.org/manifesto) · [All packages](https://lexlang.org)

A higher-level cryptographic library for [Lex](https://github.com/alpibrusl/lex-lang), built on top of `std.crypto`. Provides JWT, OAuth2/PKCE, password hashing (Argon2id), signed/sealed cookies, webhook signature verification, and TOTP.

## Modules

| Module | What it does |
|--------|-------------|
| `jwt` | Sign and verify JWTs (HS256/HS512) |
| `oauth2` | RFC 7636 PKCE helpers for OAuth2 public clients |
| `password` | Argon2id password hashing (OWASP 2024 defaults), PBKDF2, HKDF |
| `cookie` | Signed HMAC-SHA256 cookies and sealed ChaCha20-Poly1305 cookies |
| `signing` | Webhook signature verification (GitHub, Stripe, Slack, generic HMAC) |
| `totp` | RFC 6238 TOTP with SHA-256/SHA-512 |
| `base32` | RFC 4648 Base32 encode/decode (used by TOTP) |

## Installation

Add to your `lex.toml`:

```toml
[dependencies]
lex-crypto = { git = "https://github.com/alpibrusl/lex-crypto" }
```

Then run:

```sh
lex pkg install
```

## API Reference

### JWT (`src/jwt.lex`)

Sign and verify compact JWTs using HMAC-SHA256 or HMAC-SHA512.

```lex
import "lex-crypto/jwt" as jwt

type Claims = { sub :: Str, iss :: Str, aud :: Str, jti :: Str, exp :: Int, nbf :: Int, iat :: Int }

fn sign_hs256(secret :: Bytes, claims :: Claims) -> Str
fn sign_hs512(secret :: Bytes, claims :: Claims) -> Str

fn verify_hs256(secret :: Bytes, token :: Str) -> [time] Result[Claims, JwtError]
fn verify_hs512(secret :: Bytes, token :: Str) -> [time] Result[Claims, JwtError]

fn decode_unverified(token :: Str) -> Result[Claims, JwtError]

type JwtError = InvalidFormat | InvalidBase64 | InvalidSignature | Expired | NotYetValid | InvalidJson
```

**Example:**

```lex
import "std.bytes" as bytes
import "lex-crypto/jwt" as jwt

fn handle_login(secret :: Bytes) -> [time] Str {
  let claims := {
    sub: "user_42",
    iss: "myapp",
    aud: "",
    jti: "",
    exp: 1_999_999_999,
    nbf: 0,
    iat: 1_700_000_000,
  }
  jwt.sign_hs256(secret, claims)
}

fn handle_request(secret :: Bytes, token :: Str) -> [time] Result[Str, Str] {
  match jwt.verify_hs256(secret, token) {
    Err(jwt.InvalidSignature) => Err("bad token"),
    Err(jwt.Expired)          => Err("token expired"),
    Err(_)                    => Err("invalid token"),
    Ok(claims)                => Ok("hello, " + claims.sub),
  }
}
```

Use 0 for absent Int fields (`nbf`, `iat`) and `""` for absent Str fields (`aud`, `jti`). The verifier checks `exp` and `nbf` against the current clock.

---

### OAuth2 / PKCE (`src/oauth2.lex`)

RFC 7636 Proof Key for Code Exchange for OAuth2 public clients (SPAs, mobile apps).

```lex
import "lex-crypto/oauth2" as oauth2

fn pkce_verifier(entropy :: Bytes) -> Str
fn pkce_challenge(verifier :: Str) -> Str
fn pkce_verify(verifier :: Str, challenge :: Str) -> Bool

fn generate_state(entropy :: Bytes) -> Str

type AuthParams = { client_id :: Str, redirect_uri :: Str, scope :: Str, state :: Str, code_challenge :: Str }
fn build_auth_url(base_url :: Str, params :: AuthParams) -> Str

type TokenRequest = { code :: Str, redirect_uri :: Str, client_id :: Str, code_verifier :: Str }
fn build_token_request_body(req :: TokenRequest) -> Str

fn url_encode(s :: Str) -> Str
```

**Example:**

```lex
import "std.crypto" as crypto
import "lex-crypto/oauth2" as oauth2

fn start_auth_flow() -> [random] Str {
  let verifier  := oauth2.pkce_verifier(crypto.random(32))
  let challenge := oauth2.pkce_challenge(verifier)
  let state     := oauth2.generate_state(crypto.random(16))
  let params := {
    client_id:      "my_app",
    redirect_uri:   "https://app.example.com/callback",
    scope:          "openid profile email",
    state:          state,
    code_challenge: challenge,
  }
  oauth2.build_auth_url("https://auth.example.com/oauth/authorize", params)
}
```

> **Entropy**: pass `crypto.random(32)` for verifiers and `crypto.random(16)` for state. The library functions are pure — you supply the entropy.

---

### Password Hashing (`src/password.lex`)

Argon2id password hashing with OWASP 2024 recommended parameters (t=3, m=64 MB, p=4). Also provides PBKDF2-SHA256 and HKDF-SHA256 for key derivation.

```lex
import "lex-crypto/password" as password

fn hash_argon2id(password :: Str, salt :: Bytes) -> Result[Str, Str]
fn verify_argon2id(stored :: Str, password :: Str) -> Result[Bool, Str]

fn derive_key_pbkdf2(password :: Bytes, salt :: Bytes, iterations :: Int, key_len :: Int) -> Result[Bytes, Str]
fn derive_key_hkdf(ikm :: Bytes, salt :: Bytes, info :: Str, key_len :: Int) -> Result[Bytes, Str]
```

**Example:**

```lex
import "std.crypto" as crypto
import "lex-crypto/password" as pw

fn register(plain_password :: Str) -> [random] Result[Str, Str] {
  let salt := crypto.random(16)
  pw.hash_argon2id(plain_password, salt)
}

fn login(stored :: Str, plain_password :: Str) -> Result[Bool, Str] {
  pw.verify_argon2id(stored, plain_password)
}
```

The stored format is a PHC string: `$argon2id$v=19$t=3,m=65536$<salt_b64>$<hash_b64>`.

---

### Cookies (`src/cookie.lex`)

Two cookie modes:

- **Signed** — value + timestamp + HMAC-SHA256. Tamper-evident, but readable.
- **Sealed** — ChaCha20-Poly1305 AEAD. Encrypted and authenticated.

```lex
import "lex-crypto/cookie" as cookie

type CookieOptions = { max_age :: Int, secure :: Bool, http_only :: Bool, same_site :: SameSite }
type SameSite = SameSiteLax | SameSiteStrict | SameSiteNone
type CookieError = Expired | BadSignature | MalformedCookie

fn default_options() -> CookieOptions

# Signed cookies
fn sign(secret :: Bytes, value :: Str, opts :: CookieOptions) -> [time] Str
fn sign_raw(secret :: Bytes, value :: Str) -> [time] Str
fn verify(secret :: Bytes, raw :: Str, max_age_secs :: Int) -> [time] Result[Str, CookieError]

# Sealed cookies (ChaCha20-Poly1305)
fn seal(key :: Bytes, value :: Str, opts :: CookieOptions, nonce :: Bytes, ts :: Int) -> Result[Str, Str]
fn seal_raw(key :: Bytes, value :: Str, nonce :: Bytes, ts :: Int) -> Result[Str, Str]
fn unseal(key :: Bytes, raw :: Str, max_age_secs :: Int) -> [time] Result[Str, CookieError]
```

**Example:**

```lex
import "std.crypto" as crypto
import "std.time" as time
import "lex-crypto/cookie" as cookie

fn set_session(secret :: Bytes, user_id :: Str) -> [time] Str {
  let opts := cookie.default_options()
  cookie.sign(secret, user_id, opts)
}

fn get_session(secret :: Bytes, cookie_header :: Str) -> [time] Result[Str, cookie.CookieError] {
  cookie.verify(secret, cookie_header, 3600)
}

fn set_sealed_session(key :: Bytes, data :: Str) -> [random, time] Result[Str, Str] {
  let opts := cookie.default_options()
  cookie.seal(key, data, opts, crypto.random(12), time.now())
}
```

The key must be 32 bytes for ChaCha20-Poly1305. Use `max_age_secs = 0` to disable expiry checks.

---

### Webhook Signing (`src/signing.lex`)

Verify webhook payloads from GitHub, Stripe, and Slack. Also provides generic HMAC-SHA256/512.

```lex
import "lex-crypto/signing" as sign

type SignError = BadSig | MissingHeader | MissingTimestamp | StaleTimestamp(Int) | MalformedSignature

fn verify_github(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> Result[Bool, SignError]
fn verify_stripe(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> [time] Result[Bool, SignError]
fn verify_slack(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> [time] Result[Bool, SignError]

fn verify_hmac_sha256(body :: Bytes, signature :: Str, secret :: Bytes) -> Result[Bool, SignError]
fn verify_hmac_sha512(body :: Bytes, signature :: Str, secret :: Bytes) -> Result[Bool, SignError]
fn sign_hmac_sha256(secret :: Bytes, body :: Bytes) -> Str
fn sign_hmac_sha512(secret :: Bytes, body :: Bytes) -> Str
```

**Example:**

```lex
import "std.bytes" as bytes
import "lex-crypto/signing" as sign

fn handle_github_webhook(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> Result[Bool, Str] {
  match sign.verify_github(body, headers, secret) {
    Err(sign.MissingHeader) => Err("no signature header"),
    Err(sign.BadSig)        => Err("signature mismatch"),
    Err(_)                  => Err("verification failed"),
    Ok(valid)               => if valid { Ok(true) } else { Err("invalid") },
  }
}
```

- **GitHub**: reads `x-hub-signature-256` header, expects `sha256=<hex>`
- **Stripe**: reads `Stripe-Signature`, validates timestamp freshness (5 min window)
- **Slack**: reads `X-Slack-Signature` + `X-Slack-Request-Timestamp`, validates freshness (5 min)

---

### TOTP (`src/totp.lex`)

RFC 6238 Time-based One-Time Passwords using HMAC-SHA256 or HMAC-SHA512.

> **Note**: This implementation uses SHA-256/SHA-512 per RFC 6238 §1.2. Google Authenticator uses SHA-1 which is not in `std.crypto`. Use Authy, 1Password, or any RFC 6238-compliant authenticator.

```lex
import "lex-crypto/totp" as totp

type TotpAlgo = TotpSha256 | TotpSha512
type TotpConfig = { digits :: Int, period :: Int, algorithm :: TotpAlgo }

fn default_config() -> TotpConfig
fn algo_sha256() -> TotpAlgo
fn algo_sha512() -> TotpAlgo

fn generate(secret :: Bytes, config :: TotpConfig) -> [time] Str
fn generate_at(secret :: Bytes, counter :: Int, config :: TotpConfig) -> Str
fn verify(secret :: Bytes, code :: Str, config :: TotpConfig) -> [time] Bool
fn verify_at(secret :: Bytes, code :: Str, counter :: Int, config :: TotpConfig) -> Bool

fn generate_from_base32(secret_b32 :: Str, config :: TotpConfig) -> [time] Result[Str, Str]
fn verify_from_base32(secret_b32 :: Str, code :: Str, config :: TotpConfig) -> [time] Result[Bool, Str]

fn otpauth_uri(label :: Str, secret_b32 :: Str, issuer :: Str, config :: TotpConfig) -> Str
```

**Example:**

```lex
import "std.bytes" as bytes
import "lex-crypto/totp" as totp

fn setup_totp(user_email :: Str) -> Str {
  let secret_b32 := "JBSWY3DPEHPK3PXP"
  let config     := totp.default_config()
  totp.otpauth_uri(user_email, secret_b32, "MyApp", config)
}

fn verify_totp_code(secret_b32 :: Str, code :: Str) -> [time] Result[Bool, Str] {
  totp.verify_from_base32(secret_b32, code, totp.default_config())
}
```

`verify` and `verify_at` accept a ±1 step window to handle clock skew.

---

### Base32 (`src/base32.lex`)

RFC 4648 Base32 encoding and decoding, used internally by `totp`.

```lex
import "lex-crypto/base32" as base32

fn encode(data :: Bytes) -> Str
fn decode(s :: Str) -> Result[Bytes, Str]
```

---

## Design Notes

### Entropy is explicit

Functions that need randomness take entropy as a `Bytes` parameter rather than calling `crypto.random()` internally. This makes all crypto operations pure (no `[random]` effect) and testable:

```lex
# You provide entropy:
let verifier := oauth2.pkce_verifier(crypto.random(32))
let salt     := crypto.random(16)
let stored   <- password.hash_argon2id(plain_pw, salt)
let raw      <- cookie.seal_raw(key, value, crypto.random(12), time.now())
```

### Effect annotations

Functions are annotated with their effects:

| Effect | Cause |
|--------|-------|
| `[time]` | Reads the clock (`time.now()`) |
| `[random]` | **Not used** — you supply entropy |

JWT verification, cookie verification, and webhook timestamp checks use `[time]`. Signing, hashing, and encoding are pure.

### No SHA-1 TOTP

RFC 6238 specifies HMAC-SHA1 as the default. `std.crypto` does not include SHA-1 (intentionally — it's weak). This library uses HMAC-SHA256 (`TotpSha256`) and HMAC-SHA512 (`TotpSha512`). These are valid per RFC 6238 §1.2 and supported by modern authenticator apps (Authy, 1Password, Bitwarden, most enterprise OTP tools).

## Running Tests

```sh
lex test         # run all tests/test_*.lex
lex ci           # full pipeline: check + fmt + test
```

Pin the clock for time-dependent tests:

```sh
LEX_TEST_NOW=1700000000 lex test
```

## License

European Union Public Licence v1.2 (EUPL-1.2)
