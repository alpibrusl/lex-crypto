import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.time" as time

import "std.int" as int

import "./util" as util

import "./base32" as base32

type TotpAlgo = TotpSha256 | TotpSha512

type TotpConfig = { digits :: Int, period :: Int, algorithm :: TotpAlgo }

fn default_config() -> TotpConfig {
  { digits: 6, period: 30, algorithm: TotpSha256 }
}

fn algo_sha256() -> TotpAlgo {
  TotpSha256
}

fn algo_sha512() -> TotpAlgo {
  TotpSha512
}

fn generate(secret :: Bytes, config :: TotpConfig) -> [time] Str {
  let counter := time.now() / config.period
  generate_at(secret, counter, config)
}

fn generate_at(secret :: Bytes, counter :: Int, config :: TotpConfig) -> Str {
  let counter_bytes := counter_to_bytes(counter)
  let hmac := match config.algorithm {
    TotpSha256 => crypto.hmac_sha256(secret, counter_bytes),
    TotpSha512 => crypto.hmac_sha512(secret, counter_bytes),
  }
  let hmac_len := bytes.len(hmac)
  let offset := util.byte_at(hmac, hmac_len - 1) % 16
  let code := hotp_truncate(hmac, offset)
  let divisor := power10(config.digits)
  util.pad_left(int.to_str(code % divisor), config.digits, "0")
}

fn verify(secret :: Bytes, code :: Str, config :: TotpConfig) -> [time] Bool {
  let counter := time.now() / config.period
  verify_at(secret, code, counter, config)
}

fn verify_at(secret :: Bytes, code :: Str, counter :: Int, config :: TotpConfig) -> Bool {
  let prev := generate_at(secret, counter - 1, config)
  let current := generate_at(secret, counter, config)
  let next := generate_at(secret, counter + 1, config)
  crypto.eq_str(code, prev) or crypto.eq_str(code, current) or crypto.eq_str(code, next)
}

fn generate_from_base32(secret_b32 :: Str, config :: TotpConfig) -> [time] Result[Str, Str] {
  match base32.decode(secret_b32) {
    Err(e) => Err("invalid base32 secret: " + e),
    Ok(secret) => Ok(generate(secret, config)),
  }
}

fn verify_from_base32(secret_b32 :: Str, code :: Str, config :: TotpConfig) -> [time] Result[Bool, Str] {
  match base32.decode(secret_b32) {
    Err(e) => Err("invalid base32 secret: " + e),
    Ok(secret) => Ok(verify(secret, code, config)),
  }
}

fn otpauth_uri(label :: Str, secret_b32 :: Str, issuer :: Str, config :: TotpConfig) -> Str {
  let algo_str := match config.algorithm {
    TotpSha256 => "SHA256",
    TotpSha512 => "SHA512",
  }
  "otpauth://totp/" + label + "?secret=" + secret_b32 + "&issuer=" + issuer + "&algorithm=" + algo_str + "&digits=" + int.to_str(config.digits) + "&period=" + int.to_str(config.period)
}

fn counter_to_bytes(counter :: Int) -> Bytes {
  let hex := util.int_to_hex16(counter)
  match crypto.hex_decode(hex) {
    Ok(b) => b,
    Err(_) => bytes.from_str(""),
  }
}

fn hotp_truncate(hmac :: Bytes, offset :: Int) -> Int {
  let b0 := util.byte_at(hmac, offset) % 128
  let b1 := util.byte_at(hmac, offset + 1)
  let b2 := util.byte_at(hmac, offset + 2)
  let b3 := util.byte_at(hmac, offset + 3)
  b0 * 16777216 + b1 * 65536 + b2 * 256 + b3
}

fn power10(n :: Int) -> Int {
  if n <= 0 {
    1
  } else {
    10 * power10(n - 1)
  }
}

