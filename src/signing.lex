import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.time" as time

import "std.int" as int

import "std.list" as list

import "std.map" as map

type SignError = BadSig | MissingHeader | MissingTimestamp | StaleTimestamp(Int) | MalformedSignature

fn default_tolerance_secs() -> Int {
  300
}

fn verify_stripe(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> [time] Result[Bool, SignError] {
  let sig_header := map.get(headers, "stripe-signature")
  match sig_header {
    None => Err(MissingHeader),
    Some(hdr) => {
      let kv_pairs := str.split(hdr, ",")
      let t_opt := find_kv_value(kv_pairs, "t=")
      let v1_opt := find_kv_value(kv_pairs, "v1=")
      match (t_opt, v1_opt) {
        (None, _) => Err(MissingTimestamp),
        (_, None) => Err(MalformedSignature),
        (Some(ts_str), Some(sig_hex)) => {
          match str.to_int(ts_str) {
            None => Err(MalformedSignature),
            Some(ts) => {
              let now := time.now()
              if now - ts > default_tolerance_secs() {
                Err(StaleTimestamp(ts))
              } else {
                let signed_payload := ts_str + "." + string_of_bytes(body)
                let expected_hex := crypto.hex_encode(crypto.hmac_sha256(secret, bytes.from_str(signed_payload)))
                if crypto.eq_str(expected_hex, sig_hex) {
                  Ok(true)
                } else {
                  Err(BadSig)
                }
              }
            },
          }
        },
      }
    },
  }
}

fn verify_github(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> Result[Bool, SignError] {
  let sig_header := map.get(headers, "x-hub-signature-256")
  match sig_header {
    None => Err(MissingHeader),
    Some(hdr) => {
      match str.strip_prefix(hdr, "sha256=") {
        None => Err(MalformedSignature),
        Some(sig_hex) => {
          let expected_hex := crypto.hex_encode(crypto.hmac_sha256(secret, body))
          if crypto.eq_str(expected_hex, sig_hex) {
            Ok(true)
          } else {
            Err(BadSig)
          }
        },
      }
    },
  }
}

fn verify_slack(body :: Bytes, headers :: Map[Str, Str], secret :: Bytes) -> [time] Result[Bool, SignError] {
  let ts_header := map.get(headers, "x-slack-request-timestamp")
  let sig_header := map.get(headers, "x-slack-signature")
  match (ts_header, sig_header) {
    (None, _) => Err(MissingTimestamp),
    (_, None) => Err(MissingHeader),
    (Some(ts_str), Some(hdr)) => {
      match str.to_int(ts_str) {
        None => Err(MalformedSignature),
        Some(ts) => {
          let now := time.now()
          if now - ts > default_tolerance_secs() {
            Err(StaleTimestamp(ts))
          } else {
            match str.strip_prefix(hdr, "v0=") {
              None => Err(MalformedSignature),
              Some(sig_hex) => {
                let body_str := string_of_bytes(body)
                let signed_payload := "v0:" + ts_str + ":" + body_str
                let expected_hex := crypto.hex_encode(crypto.hmac_sha256(secret, bytes.from_str(signed_payload)))
                if crypto.eq_str(expected_hex, sig_hex) {
                  Ok(true)
                } else {
                  Err(BadSig)
                }
              },
            }
          }
        },
      }
    },
  }
}

fn verify_hmac_sha256(body :: Bytes, signature :: Str, secret :: Bytes) -> Result[Bool, SignError] {
  let expected := crypto.hex_encode(crypto.hmac_sha256(secret, body))
  if crypto.eq_str(expected, signature) {
    Ok(true)
  } else {
    Err(BadSig)
  }
}

fn verify_hmac_sha512(body :: Bytes, signature :: Str, secret :: Bytes) -> Result[Bool, SignError] {
  let expected := crypto.hex_encode(crypto.hmac_sha512(secret, body))
  if crypto.eq_str(expected, signature) {
    Ok(true)
  } else {
    Err(BadSig)
  }
}

fn sign_hmac_sha256(secret :: Bytes, body :: Bytes) -> Str {
  crypto.hex_encode(crypto.hmac_sha256(secret, body))
}

fn sign_hmac_sha512(secret :: Bytes, body :: Bytes) -> Str {
  crypto.hex_encode(crypto.hmac_sha512(secret, body))
}

fn find_kv_value(pairs :: List[Str], prefix :: Str) -> Option[Str] {
  let plen := str.len(prefix)
  let matched := list.filter(pairs, fn (p :: Str) -> Bool {
    str.starts_with(str.trim(p), prefix)
  })
  match list.head(matched) {
    None => None,
    Some(kv) => {
      let kv_trimmed := str.trim(kv)
      Some(str.slice(kv_trimmed, plen, str.len(kv_trimmed)))
    },
  }
}

fn string_of_bytes(b :: Bytes) -> Str {
  match bytes.to_str(b) {
    Ok(s) => s,
    Err(_) => "?",
  }
}

