import "std.str" as str

import "std.bytes" as bytes

import "../src/totp" as totp

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn make_secret() -> Bytes {
  bytes.from_str("12345678901234567890")
}

fn make_config() -> totp.TotpConfig {
  { digits: 6, period: 30, algorithm: totp.algo_sha256() }
}

fn run_all() -> [time] Int {
  test_generate_at_deterministic() + test_verify_at_window() + test_verify_at_reject_outside_window() + test_code_length() + test_base32_totp() + test_otpauth_uri()
}

fn test_generate_at_deterministic() -> Int {
  let secret := make_secret()
  let config := make_config()
  let code1 := totp.generate_at(secret, 1000, config)
  let code2 := totp.generate_at(secret, 1000, config)
  chk(code1 == code2) + chk(str.len(code1) == 6)
}

fn test_verify_at_window() -> Int {
  let secret := make_secret()
  let config := make_config()
  let counter := 5000
  let code := totp.generate_at(secret, counter, config)
  chk(totp.verify_at(secret, code, counter, config)) + chk(totp.verify_at(secret, code, counter - 1, config)) + chk(totp.verify_at(secret, code, counter + 1, config))
}

fn test_verify_at_reject_outside_window() -> Int {
  let secret := make_secret()
  let config := make_config()
  let counter := 5000
  let code := totp.generate_at(secret, counter, config)
  chk(not totp.verify_at(secret, code, counter + 2, config)) + chk(not totp.verify_at(secret, code, counter - 2, config)) + chk(not totp.verify_at(secret, "000000", counter, config))
}

fn test_code_length() -> Int {
  let secret := make_secret()
  let cfg6 := { digits: 6, period: 30, algorithm: totp.algo_sha256() }
  let cfg8 := { digits: 8, period: 30, algorithm: totp.algo_sha256() }
  let code6 := totp.generate_at(secret, 999, cfg6)
  let code8 := totp.generate_at(secret, 999, cfg8)
  chk(str.len(code6) == 6) + chk(str.len(code8) == 8)
}

fn test_base32_totp() -> [time] Int {
  let config := make_config()
  match totp.generate_from_base32("JBSWY3DPEHPK3PXP", config) {
    Err(_) => 1,
    Ok(code) => chk(str.len(code) == 6),
  }
}

fn test_otpauth_uri() -> Int {
  let uri := totp.otpauth_uri("alice@example.com", "JBSWY3DP", "MyApp", make_config())
  chk(str.starts_with(uri, "otpauth://totp/")) + chk(str.contains(uri, "secret=JBSWY3DP")) + chk(str.contains(uri, "issuer=MyApp")) + chk(str.contains(uri, "algorithm=SHA256")) + chk(str.contains(uri, "digits=6")) + chk(str.contains(uri, "period=30"))
}

