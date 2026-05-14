import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.time" as time

import "std.int" as int

import "std.list" as list

import "./util" as util

type SameSite = SameSiteLax | SameSiteStrict | SameSiteNone

type CookieOptions = { max_age :: Int, secure :: Bool, http_only :: Bool, same_site :: SameSite }

type CookieError = Expired | BadSignature | MalformedCookie

fn default_options() -> CookieOptions {
  { max_age: 3600, secure: true, http_only: true, same_site: SameSiteLax }
}

fn same_site_str(ss :: SameSite) -> Str {
  match ss {
    SameSiteLax => "Lax",
    SameSiteStrict => "Strict",
    SameSiteNone => "None",
  }
}

fn build_set_cookie(name :: Str, raw_value :: Str, opts :: CookieOptions) -> Str {
  let base := name + "=" + raw_value + "; Path=/"
  let aged := if opts.max_age > 0 {
    base + "; Max-Age=" + int.to_str(opts.max_age)
  } else {
    base
  }
  let sec := if opts.secure {
    aged + "; Secure"
  } else {
    aged
  }
  let ho := if opts.http_only {
    sec + "; HttpOnly"
  } else {
    sec
  }
  ho + "; SameSite=" + same_site_str(opts.same_site)
}

fn sign(secret :: Bytes, value :: Str, opts :: CookieOptions) -> [time] Str {
  let ts := time.now()
  let val_b64 := crypto.base64url_encode(bytes.from_str(value))
  let msg := val_b64 + "." + int.to_str(ts)
  let sig := crypto.base64url_encode(crypto.hmac_sha256(secret, bytes.from_str(msg)))
  let raw := msg + "." + sig
  build_set_cookie("session", raw, opts)
}

fn sign_raw(secret :: Bytes, value :: Str) -> [time] Str {
  let ts := time.now()
  let val_b64 := crypto.base64url_encode(bytes.from_str(value))
  let msg := val_b64 + "." + int.to_str(ts)
  let sig := crypto.base64url_encode(crypto.hmac_sha256(secret, bytes.from_str(msg)))
  msg + "." + sig
}

fn verify(secret :: Bytes, raw :: Str, max_age_secs :: Int) -> [time] Result[Str, CookieError] {
  let parts := str.split(raw, ".")
  if list.len(parts) != 3 {
    Err(MalformedCookie)
  } else {
    match list.head(parts) {
      None => Err(MalformedCookie),
      Some(val_b64) => {
        let rest1 := list.tail(parts)
        match list.head(rest1) {
          None => Err(MalformedCookie),
          Some(ts_str) => {
            match list.head(list.tail(rest1)) {
              None => Err(MalformedCookie),
              Some(sig_b64) => {
                let msg := val_b64 + "." + ts_str
                let expected_sig := crypto.hmac_sha256(secret, bytes.from_str(msg))
                match crypto.base64url_decode(sig_b64) {
                  Err(_) => Err(BadSignature),
                  Ok(actual_sig) => {
                    if not crypto.eq(expected_sig, actual_sig) {
                      Err(BadSignature)
                    } else {
                      let ts := str.to_int(ts_str)
                      match ts {
                        None => Err(MalformedCookie),
                        Some(cookie_ts) => {
                          let now := time.now()
                          if max_age_secs > 0 and now - cookie_ts > max_age_secs {
                            Err(Expired)
                          } else {
                            match crypto.base64url_decode(val_b64) {
                              Err(_) => Err(MalformedCookie),
                              Ok(val_bytes) => {
                                match bytes.to_str(val_bytes) {
                                  Err(_) => Err(MalformedCookie),
                                  Ok(value) => Ok(value),
                                }
                              },
                            }
                          }
                        },
                      }
                    }
                  },
                }
              },
            }
          },
        }
      },
    }
  }
}

fn seal(key :: Bytes, value :: Str, opts :: CookieOptions, nonce :: Bytes, ts :: Int) -> Result[Str, Str] {
  match seal_raw(key, value, nonce, ts) {
    Err(e) => Err(e),
    Ok(raw) => Ok(build_set_cookie("sealed_session", raw, opts)),
  }
}

fn seal_raw(key :: Bytes, value :: Str, nonce :: Bytes, ts :: Int) -> Result[Str, Str] {
  seal_raw_with_nonce(key, value, nonce, ts)
}

fn seal_raw_with_nonce(key :: Bytes, value :: Str, nonce :: Bytes, ts :: Int) -> Result[Str, Str] {
  let aad := bytes.from_str(int.to_str(ts))
  match crypto.chacha20_poly1305_seal(key, nonce, aad, bytes.from_str(value)) {
    Err(e) => Err("seal failed: " + e),
    Ok(aead_result) => {
      Ok(crypto.base64url_encode(nonce) + "." + crypto.base64url_encode(aead_result.ciphertext) + "." + crypto.base64url_encode(aead_result.tag) + "." + int.to_str(ts))
    },
  }
}

fn unseal(key :: Bytes, raw :: Str, max_age_secs :: Int) -> [time] Result[Str, CookieError] {
  let parts := str.split(raw, ".")
  if list.len(parts) != 4 {
    Err(MalformedCookie)
  } else {
    match list.head(parts) {
      None => Err(MalformedCookie),
      Some(nonce_b64) => {
        let rest1 := list.tail(parts)
        match list.head(rest1) {
          None => Err(MalformedCookie),
          Some(ct_b64) => {
            let rest2 := list.tail(rest1)
            match list.head(rest2) {
              None => Err(MalformedCookie),
              Some(tag_b64) => {
                match list.head(list.tail(rest2)) {
                  None => Err(MalformedCookie),
                  Some(ts_str) => {
                    let ts_opt := str.to_int(ts_str)
                    match ts_opt {
                      None => Err(MalformedCookie),
                      Some(cookie_ts) => {
                        let now := time.now()
                        if max_age_secs > 0 and now - cookie_ts > max_age_secs {
                          Err(Expired)
                        } else {
                          let aad := bytes.from_str(ts_str)
                          match crypto.base64url_decode(nonce_b64) {
                            Err(_) => Err(MalformedCookie),
                            Ok(nonce) => {
                              match crypto.base64url_decode(ct_b64) {
                                Err(_) => Err(MalformedCookie),
                                Ok(ct) => {
                                  match crypto.base64url_decode(tag_b64) {
                                    Err(_) => Err(MalformedCookie),
                                    Ok(tag) => {
                                      match crypto.chacha20_poly1305_open(key, nonce, aad, ct, tag) {
                                        Err(_) => Err(BadSignature),
                                        Ok(plaintext) => {
                                          match bytes.to_str(plaintext) {
                                            Err(_) => Err(MalformedCookie),
                                            Ok(value) => Ok(value),
                                          }
                                        },
                                      }
                                    },
                                  }
                                },
                              }
                            },
                          }
                        }
                      },
                    }
                  },
                }
              },
            }
          },
        }
      },
    }
  }
}

