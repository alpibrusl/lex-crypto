import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.time" as time

import "std.json" as json

import "std.int" as int

import "std.list" as list

import "./util" as util

type Claims = { sub :: Str, iss :: Str, aud :: Str, jti :: Str, exp :: Int, nbf :: Int, iat :: Int }

type JwtError = InvalidFormat | InvalidBase64 | InvalidSignature | Expired | NotYetValid | InvalidJson

fn default_claims() -> Claims {
  { sub: "", iss: "", aud: "", jti: "", exp: 0, nbf: 0, iat: 0 }
}

fn header_hs256() -> Str {
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
}

fn header_hs512() -> Str {
  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
}

fn claims_to_json(c :: Claims) -> Str {
  "{" + "\"sub\":\"" + util.json_escape(c.sub) + "\"," + "\"iss\":\"" + util.json_escape(c.iss) + "\"," + "\"aud\":\"" + util.json_escape(c.aud) + "\"," + "\"jti\":\"" + util.json_escape(c.jti) + "\"," + "\"exp\":" + int.to_str(c.exp) + "," + "\"nbf\":" + int.to_str(c.nbf) + "," + "\"iat\":" + int.to_str(c.iat) + "}"
}

fn sign_hs256(secret :: Bytes, claims :: Claims) -> Str {
  let payload := crypto.base64url_encode(bytes.from_str(claims_to_json(claims)))
  let signing_input := header_hs256() + "." + payload
  let sig := crypto.base64url_encode(crypto.hmac_sha256(secret, bytes.from_str(signing_input)))
  signing_input + "." + sig
}

fn sign_hs512(secret :: Bytes, claims :: Claims) -> Str {
  let payload := crypto.base64url_encode(bytes.from_str(claims_to_json(claims)))
  let signing_input := header_hs512() + "." + payload
  let sig := crypto.base64url_encode(crypto.hmac_sha512(secret, bytes.from_str(signing_input)))
  signing_input + "." + sig
}

fn verify_hs256(secret :: Bytes, token :: Str) -> [time] Result[Claims, JwtError] {
  verify_token(secret, token, "HS256")
}

fn verify_hs512(secret :: Bytes, token :: Str) -> [time] Result[Claims, JwtError] {
  verify_token(secret, token, "HS512")
}

fn verify_token(secret :: Bytes, token :: Str, alg :: Str) -> [time] Result[Claims, JwtError] {
  let parts := str.split(token, ".")
  if list.len(parts) != 3 {
    Err(InvalidFormat)
  } else {
    match list.head(parts) {
      None => Err(InvalidFormat),
      Some(header_b64) => {
        let rest1 := list.tail(parts)
        match list.head(rest1) {
          None => Err(InvalidFormat),
          Some(payload_b64) => {
            let rest2 := list.tail(rest1)
            match list.head(rest2) {
              None => Err(InvalidFormat),
              Some(sig_b64) => {
                let signing_input := header_b64 + "." + payload_b64
                let expected_sig := if alg == "HS256" {
                  crypto.hmac_sha256(secret, bytes.from_str(signing_input))
                } else {
                  crypto.hmac_sha512(secret, bytes.from_str(signing_input))
                }
                match crypto.base64url_decode(sig_b64) {
                  Err(_) => Err(InvalidBase64),
                  Ok(actual_sig) => {
                    if not crypto.eq(expected_sig, actual_sig) {
                      Err(InvalidSignature)
                    } else {
                      match crypto.base64url_decode(payload_b64) {
                        Err(_) => Err(InvalidBase64),
                        Ok(payload_bytes) => {
                          match bytes.to_str(payload_bytes) {
                            Err(_) => Err(InvalidJson),
                            Ok(payload_str) => {
                              match (json.parse(payload_str) :: Result[Claims, Str]) {
                                Err(_) => Err(InvalidJson),
                                Ok(claims) => {
                                  let now := time.now()
                                  if claims.exp > 0 and claims.exp < now {
                                    Err(Expired)
                                  } else {
                                    if claims.nbf > 0 and claims.nbf > now {
                                      Err(NotYetValid)
                                    } else {
                                      Ok(claims)
                                    }
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
  }
}

fn decode_unverified(token :: Str) -> Result[Claims, JwtError] {
  let parts := str.split(token, ".")
  if list.len(parts) != 3 {
    Err(InvalidFormat)
  } else {
    let rest := list.tail(parts)
    match list.head(rest) {
      None => Err(InvalidFormat),
      Some(payload_b64) => {
        match crypto.base64url_decode(payload_b64) {
          Err(_) => Err(InvalidBase64),
          Ok(payload_bytes) => {
            match bytes.to_str(payload_bytes) {
              Err(_) => Err(InvalidJson),
              Ok(payload_str) => {
                match (json.parse(payload_str) :: Result[Claims, Str]) {
                  Err(_) => Err(InvalidJson),
                  Ok(claims) => Ok(claims),
                }
              },
            }
          },
        }
      },
    }
  }
}

