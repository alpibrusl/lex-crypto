import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.int" as int

import "std.list" as list

import "./util" as util

fn argon2id_t_cost() -> Int {
  3
}

fn argon2id_m_cost() -> Int {
  65536
}

fn argon2id_hash_len() -> Int {
  32
}

fn argon2id_salt_len() -> Int {
  16
}

fn make_stored(t :: Int, m :: Int, salt :: Bytes, hash :: Bytes) -> Str {
  "$argon2id$v=19$t=" + int.to_str(t) + ",m=" + int.to_str(m) + "$" + crypto.base64_encode(salt) + "$" + crypto.base64_encode(hash)
}

fn hash_argon2id(password :: Str, salt :: Bytes) -> Result[Str, Str] {
  let result := crypto.argon2id(bytes.from_str(password), salt, argon2id_t_cost(), argon2id_m_cost(), argon2id_hash_len())
  match result {
    Err(e) => Err("argon2id failed: " + e),
    Ok(hash) => Ok(make_stored(argon2id_t_cost(), argon2id_m_cost(), salt, hash)),
  }
}

fn verify_argon2id(stored :: Str, password :: Str) -> Result[Bool, Str] {
  let parts := str.split(stored, "$")
  if list.len(parts) != 6 {
    Err("invalid stored password format")
  } else {
    match list.head(list.tail(list.tail(list.tail(list.tail(parts))))) {
      None => Err("missing salt in stored password"),
      Some(salt_b64) => {
        match list.head(list.tail(list.tail(list.tail(list.tail(list.tail(parts)))))) {
          None => Err("missing hash in stored password"),
          Some(hash_b64) => {
            match list.head(list.tail(list.tail(list.tail(parts)))) {
              None => Err("missing params in stored password"),
              Some(params) => {
                let parsed := parse_argon2_params(params)
                match parsed {
                  Err(e) => Err(e),
                  Ok(tc_mc) => {
                    let tc := tc_mc.t_cost
                    let mc := tc_mc.m_cost
                    match crypto.base64_decode(salt_b64) {
                      Err(_) => Err("invalid salt encoding"),
                      Ok(salt) => {
                        match crypto.base64_decode(hash_b64) {
                          Err(_) => Err("invalid hash encoding"),
                          Ok(hash_want) => {
                            let result := crypto.argon2id(bytes.from_str(password), salt, tc, mc, bytes.len(hash_want))
                            match result {
                              Err(e) => Err("argon2id failed: " + e),
                              Ok(hash_got) => Ok(crypto.eq(hash_got, hash_want)),
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
      },
    }
  }
}

type Argon2Params = { t_cost :: Int, m_cost :: Int }

fn parse_argon2_params(s :: Str) -> Result[Argon2Params, Str] {
  let kv_pairs := str.split(s, ",")
  let t_opt := find_param(kv_pairs, "t=")
  let m_opt := find_param(kv_pairs, "m=")
  match (t_opt, m_opt) {
    (None, _) => Err("missing t_cost in argon2 params"),
    (_, None) => Err("missing m_cost in argon2 params"),
    (Some(t), Some(m)) => Ok({ t_cost: t, m_cost: m }),
  }
}

fn find_param(pairs :: List[Str], prefix :: Str) -> Option[Int] {
  let matched := list.filter(pairs, fn (p :: Str) -> Bool {
    str.starts_with(p, prefix)
  })
  match list.head(matched) {
    None => None,
    Some(kv) => {
      let val_str := str.slice(kv, str.len(prefix), str.len(kv))
      str.to_int(val_str)
    },
  }
}

fn derive_key_pbkdf2(password :: Bytes, salt :: Bytes, iterations :: Int, key_len :: Int) -> Result[Bytes, Str] {
  crypto.pbkdf2_sha256(password, salt, iterations, key_len)
}

fn derive_key_hkdf(ikm :: Bytes, salt :: Bytes, info :: Str, key_len :: Int) -> Result[Bytes, Str] {
  crypto.hkdf_sha256(ikm, salt, bytes.from_str(info), key_len)
}

