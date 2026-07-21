import "std.bytes" as bytes

import "std.str" as str

import "std.list" as list

import "../src/jwt" as jwt

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn run_all() -> [time] Int {
  let failures := test_sign_verify_hs256() + test_sign_verify_hs512() + test_invalid_signature() + test_invalid_format() + test_decode_unverified() + test_claims_serialization() + test_sign_hs256_kid()
  if failures == 0 {
    0
  } else {
    let __fail := 1 / 0
    failures
  }
}

fn make_secret() -> Bytes {
  bytes.from_str("super-secret-key-for-testing-only")
}

fn make_claims() -> jwt.Claims {
  { sub: "user_123", iss: "myapp", aud: "", jti: "", exp: 1999999999, nbf: 0, iat: 1700000000 }
}

fn test_sign_verify_hs256() -> [time] Int {
  let secret := make_secret()
  let claims := make_claims()
  let token := jwt.sign_hs256(secret, claims)
  let parts := str.split(token, ".")
  let f1 := chk(list.len(parts) == 3)
  let f2 := match jwt.verify_hs256(secret, token) {
    Err(_) => 1,
    Ok(c) => chk(c.sub == "user_123") + chk(c.iss == "myapp") + chk(c.exp == 1999999999),
  }
  f1 + f2
}

fn test_sign_verify_hs512() -> [time] Int {
  let secret := make_secret()
  let claims := make_claims()
  let token := jwt.sign_hs512(secret, claims)
  match jwt.verify_hs512(secret, token) {
    Err(_) => 1,
    Ok(c) => chk(c.sub == "user_123"),
  }
}

fn test_invalid_signature() -> [time] Int {
  let secret := make_secret()
  let claims := make_claims()
  let token := jwt.sign_hs256(secret, claims)
  let bad_key := bytes.from_str("wrong-secret-key-padding-padding!")
  match jwt.verify_hs256(bad_key, token) {
    Ok(_) => 1,
    Err(InvalidSignature) => 0,
    Err(_) => 1,
  }
}

fn test_invalid_format() -> [time] Int {
  let f1 := match jwt.verify_hs256(make_secret(), "not.a.token.at.all") {
    Err(InvalidFormat) => 0,
    _ => 1,
  }
  let f2 := match jwt.verify_hs256(make_secret(), "onlyone") {
    Err(InvalidFormat) => 0,
    _ => 1,
  }
  f1 + f2
}

fn test_decode_unverified() -> Int {
  let secret := make_secret()
  let claims := make_claims()
  let token := jwt.sign_hs256(secret, claims)
  match jwt.decode_unverified(token) {
    Err(_) => 1,
    Ok(c) => chk(c.sub == "user_123"),
  }
}

fn test_claims_serialization() -> [time] Int {
  let secret := make_secret()
  let full_claims := { sub: "alice", iss: "auth.example.com", aud: "api.example.com", jti: "unique-id-123", exp: 9999999999, nbf: 1000000000, iat: 1700000000 }
  let token := jwt.sign_hs256(secret, full_claims)
  match jwt.verify_hs256(secret, token) {
    Err(_) => 1,
    Ok(c) => chk(c.sub == "alice") + chk(c.iss == "auth.example.com") + chk(c.aud == "api.example.com") + chk(c.jti == "unique-id-123") + chk(c.exp == 9999999999) + chk(c.nbf == 1000000000) + chk(c.iat == 1700000000),
  }
}

# A kid-stamped token: verifies with the same secret (the kid header is covered
# by the signature), token_kid recovers the id, and a plain token has no kid.
fn test_sign_hs256_kid() -> [time] Int {
  let secret := make_secret()
  let claims := make_claims()
  let token := jwt.sign_hs256_kid(secret, "key-2026-07", claims)
  let f1 := match jwt.verify_hs256(secret, token) {
    Err(_) => 1,
    Ok(c) => chk(c.sub == "user_123"),
  }
  let f2 := match jwt.token_kid(token) {
    Some(k) => chk(k == "key-2026-07"),
    None => 1,
  }
  let f3 := match jwt.token_kid(jwt.sign_hs256(secret, claims)) {
    None => 0,
    Some(_) => 1,
  }
  let f4 := match jwt.verify_hs256(bytes.from_str("wrong-secret-entirely-nope"), token) {
    Err(_) => 0,
    Ok(_) => 1,
  }
  f1 + f2 + f3 + f4
}

