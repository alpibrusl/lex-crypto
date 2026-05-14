import "std.bytes" as bytes

import "std.str" as str

import "../src/cookie" as cookie

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn make_secret() -> Bytes {
  bytes.from_str("test-cookie-secret-key-32-bytes!")
}

fn make_aead_key() -> Bytes {
  bytes.from_str("test-aead-key-for-sealing-32-by!")
}

fn fixed_nonce() -> Bytes {
  bytes.from_str("nonce-12bytes")
}

fn run_all() -> [time] Int {
  test_sign_verify_roundtrip() + test_expired_cookie() + test_tampered_cookie() + test_seal_unseal_roundtrip() + test_set_cookie_header()
}

fn test_sign_verify_roundtrip() -> [time] Int {
  let secret := make_secret()
  let raw := cookie.sign_raw(secret, "user_session_data")
  match cookie.verify(secret, raw, 3600) {
    Err(_) => 1,
    Ok(val) => chk(val == "user_session_data"),
  }
}

fn test_expired_cookie() -> [time] Int {
  let secret := make_secret()
  let raw := cookie.sign_raw(secret, "data")
  match cookie.verify(secret, raw, 0) {
    Err(_) => 1,
    Ok(val) => chk(val == "data"),
  }
}

fn test_tampered_cookie() -> [time] Int {
  let secret := make_secret()
  let raw := cookie.sign_raw(secret, "user_id=42")
  let tampered := str.replace(raw, "dXNlcl9pZD00Mg", "dXNlcl9pZD05OQ")
  match cookie.verify(secret, tampered, 3600) {
    Err(BadSignature) => 0,
    Err(MalformedCookie) => 0,
    Ok(_) => 1,
    Err(_) => 0,
  }
}

fn test_seal_unseal_roundtrip() -> [time] Int {
  let key := make_aead_key()
  let ts := 1700000000
  match cookie.seal_raw(key, "secret_session_value", fixed_nonce(), ts) {
    Err(_) => 1,
    Ok(raw) => {
      match cookie.unseal(key, raw, 0) {
        Err(_) => 1,
        Ok(val) => chk(val == "secret_session_value"),
      }
    },
  }
}

fn test_set_cookie_header() -> [time] Int {
  let secret := make_secret()
  let opts := cookie.default_options()
  let header := cookie.sign(secret, "val", opts)
  chk(str.contains(header, "session=")) + chk(str.contains(header, "; Secure")) + chk(str.contains(header, "; HttpOnly")) + chk(str.contains(header, "; SameSite=")) + chk(str.contains(header, "Max-Age="))
}

