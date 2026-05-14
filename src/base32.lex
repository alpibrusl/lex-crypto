import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.int" as int

import "./util" as util

fn alphabet() -> Str {
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
}

fn encode_char(idx :: Int) -> Str {
  str.slice(alphabet(), idx, idx + 1)
}

fn decode_char(c :: Str) -> Int {
  match str.to_upper(c) {
    "A" => 0,
    "B" => 1,
    "C" => 2,
    "D" => 3,
    "E" => 4,
    "F" => 5,
    "G" => 6,
    "H" => 7,
    "I" => 8,
    "J" => 9,
    "K" => 10,
    "L" => 11,
    "M" => 12,
    "N" => 13,
    "O" => 14,
    "P" => 15,
    "Q" => 16,
    "R" => 17,
    "S" => 18,
    "T" => 19,
    "U" => 20,
    "V" => 21,
    "W" => 22,
    "X" => 23,
    "Y" => 24,
    "Z" => 25,
    "2" => 26,
    "3" => 27,
    "4" => 28,
    "5" => 29,
    "6" => 30,
    "7" => 31,
    _ => -1,
  }
}

fn get_char_val(s :: Str, pos :: Int) -> Result[Int, Str] {
  let c := str.slice(s, pos, pos + 1)
  let v := decode_char(c)
  if v == -1 {
    Err("invalid base32 character: " + c)
  } else {
    Ok(v)
  }
}

fn encode_5bytes(b0 :: Int, b1 :: Int, b2 :: Int, b3 :: Int, b4 :: Int) -> Str {
  encode_char(b0 / 8) + encode_char(b0 % 8 * 4 + b1 / 64) + encode_char(b1 / 2 % 32) + encode_char(b1 % 2 * 16 + b2 / 16) + encode_char(b2 % 16 * 2 + b3 / 128) + encode_char(b3 / 4 % 32) + encode_char(b3 % 4 * 8 + b4 / 32) + encode_char(b4 % 32)
}

fn encode(b :: Bytes) -> Str {
  encode_loop(b, bytes.len(b), 0, "")
}

fn encode_loop(b :: Bytes, len :: Int, pos :: Int, acc :: Str) -> Str {
  let remaining := len - pos
  if remaining <= 0 {
    acc
  } else {
    if remaining >= 5 {
      let block := encode_5bytes(util.byte_at(b, pos), util.byte_at(b, pos + 1), util.byte_at(b, pos + 2), util.byte_at(b, pos + 3), util.byte_at(b, pos + 4))
      encode_loop(b, len, pos + 5, acc + block)
    } else {
      acc + encode_tail(b, pos, remaining)
    }
  }
}

fn encode_tail(b :: Bytes, pos :: Int, remaining :: Int) -> Str {
  let b0 := util.byte_at(b, pos)
  if remaining == 1 {
    encode_char(b0 / 8) + encode_char(b0 % 8 * 4) + "======"
  } else {
    let b1 := util.byte_at(b, pos + 1)
    if remaining == 2 {
      encode_char(b0 / 8) + encode_char(b0 % 8 * 4 + b1 / 64) + encode_char(b1 / 2 % 32) + encode_char(b1 % 2 * 16) + "===="
    } else {
      let b2 := util.byte_at(b, pos + 2)
      if remaining == 3 {
        encode_char(b0 / 8) + encode_char(b0 % 8 * 4 + b1 / 64) + encode_char(b1 / 2 % 32) + encode_char(b1 % 2 * 16 + b2 / 16) + encode_char(b2 % 16 * 2) + "==="
      } else {
        let b3 := util.byte_at(b, pos + 3)
        encode_char(b0 / 8) + encode_char(b0 % 8 * 4 + b1 / 64) + encode_char(b1 / 2 % 32) + encode_char(b1 % 2 * 16 + b2 / 16) + encode_char(b2 % 16 * 2 + b3 / 128) + encode_char(b3 / 4 % 32) + encode_char(b3 % 4 * 8) + "="
      }
    }
  }
}

fn decode(s :: Str) -> Result[Bytes, Str] {
  let stripped := str.replace(str.to_upper(str.trim(s)), "=", "")
  let slen := str.len(stripped)
  if slen == 0 {
    Ok(bytes.from_str(""))
  } else {
    decode_loop(stripped, slen, 0, "")
  }
}

fn decode_loop(s :: Str, slen :: Int, pos :: Int, hex_acc :: Str) -> Result[Bytes, Str] {
  if pos >= slen {
    crypto.hex_decode(hex_acc)
  } else {
    let remaining := slen - pos
    if remaining >= 8 {
      let r := decode_8(s, pos)
      match r {
        Err(e) => Err(e),
        Ok(chunk) => decode_loop(s, slen, pos + 8, hex_acc + chunk),
      }
    } else {
      let r := decode_partial(s, pos, remaining)
      match r {
        Err(e) => Err(e),
        Ok(chunk) => decode_loop(s, slen, slen, hex_acc + chunk),
      }
    }
  }
}

fn decode_8(s :: Str, pos :: Int) -> Result[Str, Str] {
  let r0 := get_char_val(s, pos)
  let r1 := get_char_val(s, pos + 1)
  let r2 := get_char_val(s, pos + 2)
  let r3 := get_char_val(s, pos + 3)
  let r4 := get_char_val(s, pos + 4)
  let r5 := get_char_val(s, pos + 5)
  let r6 := get_char_val(s, pos + 6)
  let r7 := get_char_val(s, pos + 7)
  match (r0, r1, r2, r3, r4, r5, r6, r7) {
    (Ok(c0), Ok(c1), Ok(c2), Ok(c3), Ok(c4), Ok(c5), Ok(c6), Ok(c7)) => Ok(util.byte_to_hex(c0 * 8 + c1 / 4) + util.byte_to_hex(c1 % 4 * 64 + c2 * 2 + c3 / 16) + util.byte_to_hex(c3 % 16 * 16 + c4 / 2) + util.byte_to_hex(c4 % 2 * 128 + c5 * 4 + c6 / 8) + util.byte_to_hex(c6 % 8 * 32 + c7)),
    (Err(e), _, _, _, _, _, _, _) => Err(e),
    (_, Err(e), _, _, _, _, _, _) => Err(e),
    (_, _, Err(e), _, _, _, _, _) => Err(e),
    (_, _, _, Err(e), _, _, _, _) => Err(e),
    (_, _, _, _, Err(e), _, _, _) => Err(e),
    (_, _, _, _, _, Err(e), _, _) => Err(e),
    (_, _, _, _, _, _, Err(e), _) => Err(e),
    (_, _, _, _, _, _, _, Err(e)) => Err(e),
  }
}

fn decode_partial(s :: Str, pos :: Int, remaining :: Int) -> Result[Str, Str] {
  if remaining == 7 {
    decode_7(s, pos)
  } else {
    if remaining == 5 {
      decode_5(s, pos)
    } else {
      if remaining == 4 {
        decode_4(s, pos)
      } else {
        if remaining == 2 {
          decode_2(s, pos)
        } else {
          Err("invalid base32: bad padding length")
        }
      }
    }
  }
}

fn decode_7(s :: Str, pos :: Int) -> Result[Str, Str] {
  let r0 := get_char_val(s, pos)
  let r1 := get_char_val(s, pos + 1)
  let r2 := get_char_val(s, pos + 2)
  let r3 := get_char_val(s, pos + 3)
  let r4 := get_char_val(s, pos + 4)
  let r5 := get_char_val(s, pos + 5)
  let r6 := get_char_val(s, pos + 6)
  match (r0, r1, r2, r3, r4, r5, r6) {
    (Ok(c0), Ok(c1), Ok(c2), Ok(c3), Ok(c4), Ok(c5), Ok(c6)) => Ok(util.byte_to_hex(c0 * 8 + c1 / 4) + util.byte_to_hex(c1 % 4 * 64 + c2 * 2 + c3 / 16) + util.byte_to_hex(c3 % 16 * 16 + c4 / 2) + util.byte_to_hex(c4 % 2 * 128 + c5 * 4 + c6 / 8)),
    (Err(e), _, _, _, _, _, _) => Err(e),
    (_, Err(e), _, _, _, _, _) => Err(e),
    (_, _, Err(e), _, _, _, _) => Err(e),
    (_, _, _, Err(e), _, _, _) => Err(e),
    (_, _, _, _, Err(e), _, _) => Err(e),
    (_, _, _, _, _, Err(e), _) => Err(e),
    (_, _, _, _, _, _, Err(e)) => Err(e),
  }
}

fn decode_5(s :: Str, pos :: Int) -> Result[Str, Str] {
  let r0 := get_char_val(s, pos)
  let r1 := get_char_val(s, pos + 1)
  let r2 := get_char_val(s, pos + 2)
  let r3 := get_char_val(s, pos + 3)
  let r4 := get_char_val(s, pos + 4)
  match (r0, r1, r2, r3, r4) {
    (Ok(c0), Ok(c1), Ok(c2), Ok(c3), Ok(c4)) => Ok(util.byte_to_hex(c0 * 8 + c1 / 4) + util.byte_to_hex(c1 % 4 * 64 + c2 * 2 + c3 / 16) + util.byte_to_hex(c3 % 16 * 16 + c4 / 2)),
    (Err(e), _, _, _, _) => Err(e),
    (_, Err(e), _, _, _) => Err(e),
    (_, _, Err(e), _, _) => Err(e),
    (_, _, _, Err(e), _) => Err(e),
    (_, _, _, _, Err(e)) => Err(e),
  }
}

fn decode_4(s :: Str, pos :: Int) -> Result[Str, Str] {
  let r0 := get_char_val(s, pos)
  let r1 := get_char_val(s, pos + 1)
  let r2 := get_char_val(s, pos + 2)
  let r3 := get_char_val(s, pos + 3)
  match (r0, r1, r2, r3) {
    (Ok(c0), Ok(c1), Ok(c2), Ok(c3)) => Ok(util.byte_to_hex(c0 * 8 + c1 / 4) + util.byte_to_hex(c1 % 4 * 64 + c2 * 2 + c3 / 16)),
    (Err(e), _, _, _) => Err(e),
    (_, Err(e), _, _) => Err(e),
    (_, _, Err(e), _) => Err(e),
    (_, _, _, Err(e)) => Err(e),
  }
}

fn decode_2(s :: Str, pos :: Int) -> Result[Str, Str] {
  let r0 := get_char_val(s, pos)
  let r1 := get_char_val(s, pos + 1)
  match (r0, r1) {
    (Ok(c0), Ok(c1)) => Ok(util.byte_to_hex(c0 * 8 + c1 / 4)),
    (Err(e), _) => Err(e),
    (_, Err(e)) => Err(e),
  }
}

