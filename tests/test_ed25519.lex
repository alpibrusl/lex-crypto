import "std.bytes" as bytes

import "../src/ed25519" as ed

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

# A deterministic 32-byte secret seed (tests don't need randomness).
fn secret() -> Bytes {
  bytes.from_str("01234567890123456789012345678901")
}

fn run_all() -> Int {
  test_roundtrip() + test_tampered_message() + test_wrong_key() + test_bad_secret_len() + test_text_roundtrip() + test_text_tampered()
}

fn test_roundtrip() -> Int {
  let msg := bytes.from_str("transfer authorized")
  match ed.public_key(secret()) {
    Err(_) => 1,
    Ok(pk) => match ed.sign(secret(), msg) {
      Err(_) => 1,
      Ok(sig) => chk(ed.verify(pk, msg, sig)),
    },
  }
}

fn test_tampered_message() -> Int {
  let msg := bytes.from_str("transfer 100")
  match ed.public_key(secret()) {
    Err(_) => 1,
    Ok(pk) => match ed.sign(secret(), msg) {
      Err(_) => 1,
      Ok(sig) => chk(not ed.verify(pk, bytes.from_str("transfer 9999"), sig)),
    },
  }
}

fn test_wrong_key() -> Int {
  let msg := bytes.from_str("hello")
  let other := bytes.from_str("ZZZZ567890123456789012345678901Z")
  match ed.sign(secret(), msg) {
    Err(_) => 1,
    Ok(sig) => match ed.public_key(other) {
      Err(_) => 1,
      Ok(other_pk) => chk(not ed.verify(other_pk, msg, sig)),
    },
  }
}

fn test_bad_secret_len() -> Int {
  match ed.public_key(bytes.from_str("too-short")) {
    Err(_) => 0,
    Ok(_) => 1,
  }
}

fn test_text_roundtrip() -> Int {
  match ed.public_key_b64(secret()) {
    Err(_) => 1,
    Ok(pkb64) => match ed.sign_text(secret(), "org=fastned;url=https://fastned.example") {
      Err(_) => 1,
      Ok(sigb64) => chk(ed.verify_text(pkb64, "org=fastned;url=https://fastned.example", sigb64)),
    },
  }
}

fn test_text_tampered() -> Int {
  match ed.public_key_b64(secret()) {
    Err(_) => 1,
    Ok(pkb64) => match ed.sign_text(secret(), "org=fastned") {
      Err(_) => 1,
      Ok(sigb64) => chk(not ed.verify_text(pkb64, "org=impostor", sigb64)),
    },
  }
}

