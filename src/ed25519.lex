# ed25519.lex — asymmetric (public-key) signatures.
#
# Thin, ergonomic wrappers over the std.crypto ed25519 builtins (#643). Unlike
# HMAC/JWT (symmetric — verifier needs the secret), ed25519 lets ANY party verify
# a signature against a published PUBLIC key. Use it to sign artifacts a third
# party must authenticate without sharing a secret: agent cards, catalogs,
# software releases, webhooks, etc.
#
# A secret key IS its 32-byte seed — generate one with `crypto.random(32)`
# (requires the `random` effect) and derive the public key with `public_key`.

import "std.crypto" as crypto

import "std.bytes" as bytes

# Derive the 32-byte public key from a 32-byte secret seed.
fn public_key(secret :: Bytes) -> Result[Bytes, Str] {
  crypto.ed25519_public_key(secret)
}

# 64-byte detached signature over `message`.
fn sign(secret :: Bytes, message :: Bytes) -> Result[Bytes, Str] {
  crypto.ed25519_sign(secret, message)
}

# Verify a detached signature. False on any malformed input (wrong key/sig length,
# bad signature) — never panics.
fn verify(public :: Bytes, message :: Bytes, signature :: Bytes) -> Bool {
  crypto.ed25519_verify(public, message, signature)
}

# ── base64url string convenience (for cards / tokens / URLs) ──────────────────

# Public key as a base64url string.
fn public_key_b64(secret :: Bytes) -> Result[Str, Str] {
  match crypto.ed25519_public_key(secret) {
    Ok(pk) => Ok(crypto.base64url_encode(pk)),
    Err(e) => Err(e),
  }
}

# Sign a text message; return the signature as base64url.
fn sign_text(secret :: Bytes, text :: Str) -> Result[Str, Str] {
  match crypto.ed25519_sign(secret, bytes.from_str(text)) {
    Ok(sig) => Ok(crypto.base64url_encode(sig)),
    Err(e) => Err(e),
  }
}

# Verify a base64url signature over `text` against a base64url public key.
# Any decode failure or bad signature returns false.
fn verify_text(public_b64 :: Str, text :: Str, signature_b64 :: Str) -> Bool {
  match crypto.base64url_decode(public_b64) {
    Err(_) => false,
    Ok(pub) => match crypto.base64url_decode(signature_b64) {
      Err(_) => false,
      Ok(sig) => crypto.ed25519_verify(pub, bytes.from_str(text), sig),
    },
  }
}
