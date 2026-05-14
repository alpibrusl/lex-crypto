import "std.bytes" as bytes

import "std.map" as map

import "../src/signing" as sign

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn make_secret() -> Bytes {
  bytes.from_str("webhook-secret-key")
}

fn make_body() -> Bytes {
  bytes.from_str("{\"event\":\"push\",\"repo\":\"my-repo\"}")
}

fn run_all() -> [time] Int {
  test_verify_github() + test_verify_github_bad_sig() + test_verify_hmac_sha256() + test_verify_hmac_sha256_bad_sig() + test_sign_and_verify() + test_missing_header()
}

fn test_verify_github() -> Int {
  let secret := make_secret()
  let body := make_body()
  let sig := "sha256=" + sign.sign_hmac_sha256(secret, body)
  let headers := map.set(map.new(), "x-hub-signature-256", sig)
  match sign.verify_github(body, headers, secret) {
    Err(_) => 1,
    Ok(passed) => chk(passed),
  }
}

fn test_verify_github_bad_sig() -> Int {
  let secret := make_secret()
  let body := make_body()
  let bad_sig := "sha256=0000000000000000000000000000000000000000000000000000000000000000"
  let headers := map.set(map.new(), "x-hub-signature-256", bad_sig)
  match sign.verify_github(body, headers, secret) {
    Err(BadSig) => 0,
    Ok(_) => 1,
    Err(_) => 1,
  }
}

fn test_verify_hmac_sha256() -> Int {
  let secret := make_secret()
  let body := make_body()
  let sig := sign.sign_hmac_sha256(secret, body)
  match sign.verify_hmac_sha256(body, sig, secret) {
    Err(_) => 1,
    Ok(passed) => chk(passed),
  }
}

fn test_verify_hmac_sha256_bad_sig() -> Int {
  let secret := make_secret()
  let body := make_body()
  match sign.verify_hmac_sha256(body, "deadbeefdeadbeef", secret) {
    Err(BadSig) => 0,
    Ok(_) => 1,
    Err(_) => 1,
  }
}

fn test_sign_and_verify() -> Int {
  let secret := bytes.from_str("another-secret")
  let body := bytes.from_str("some payload data")
  let sig256 := sign.sign_hmac_sha256(secret, body)
  let sig512 := sign.sign_hmac_sha512(secret, body)
  let f1 := match sign.verify_hmac_sha256(body, sig256, secret) {
    Ok(t) => chk(t),
    Err(_) => 1,
  }
  let f2 := match sign.verify_hmac_sha512(body, sig512, secret) {
    Ok(t) => chk(t),
    Err(_) => 1,
  }
  let f3 := match sign.verify_hmac_sha512(body, sig256, secret) {
    Ok(t) => chk(not t),
    Err(_) => 0,
  }
  f1 + f2 + f3
}

fn test_missing_header() -> Int {
  let secret := make_secret()
  let body := make_body()
  let headers := map.new()
  match sign.verify_github(body, headers, secret) {
    Err(MissingHeader) => 0,
    _ => 1,
  }
}

