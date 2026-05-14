import "std.str" as str

import "std.bytes" as bytes

import "../src/password" as pw

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn fixed_salt() -> Bytes {
  bytes.from_str("0123456789abcdef")
}

fn fixed_salt2() -> Bytes {
  bytes.from_str("fedcba9876543210")
}

fn run_all() -> Int {
  test_hash_format() + test_verify_roundtrip() + test_wrong_password() + test_different_salts() + test_pbkdf2_derive() + test_hkdf_derive()
}

fn test_hash_format() -> Int {
  match pw.hash_argon2id("secret123", fixed_salt()) {
    Err(_) => 1,
    Ok(stored) => chk(str.starts_with(stored, "$argon2id$")) + chk(str.contains(stored, "$v=19$")) + chk(str.contains(stored, "$t=3,m=65536$")),
  }
}

fn test_verify_roundtrip() -> Int {
  let password := "correct-horse-battery-staple"
  match pw.hash_argon2id(password, fixed_salt()) {
    Err(_) => 1,
    Ok(stored) => {
      match pw.verify_argon2id(stored, password) {
        Err(_) => 1,
        Ok(passed) => chk(passed),
      }
    },
  }
}

fn test_wrong_password() -> Int {
  let password := "correct-horse-battery-staple"
  match pw.hash_argon2id(password, fixed_salt()) {
    Err(_) => 1,
    Ok(stored) => {
      match pw.verify_argon2id(stored, "wrong-password") {
        Err(_) => 1,
        Ok(passed) => chk(not passed),
      }
    },
  }
}

fn test_different_salts() -> Int {
  let r1 := pw.hash_argon2id("password", fixed_salt())
  let r2 := pw.hash_argon2id("password", fixed_salt2())
  match r1 {
    Err(_) => 1,
    Ok(h1) => {
      match r2 {
        Err(_) => 1,
        Ok(h2) => chk(h1 != h2),
      }
    },
  }
}

fn test_pbkdf2_derive() -> Int {
  let pass := bytes.from_str("test-password")
  let salt := bytes.from_str("test-salt-12345")
  match pw.derive_key_pbkdf2(pass, salt, 600000, 32) {
    Err(_) => 1,
    Ok(key) => chk(bytes.len(key) == 32),
  }
}

fn test_hkdf_derive() -> Int {
  let ikm := bytes.from_str("input-key-material")
  let salt := bytes.from_str("random-salt")
  match pw.derive_key_hkdf(ikm, salt, "context-info", 32) {
    Err(_) => 1,
    Ok(key) => chk(bytes.len(key) == 32),
  }
}

