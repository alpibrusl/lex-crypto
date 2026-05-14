import "std.str" as str

import "std.bytes" as bytes

import "../src/base32" as base32

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn run_all() -> Int {
  test_encode_known_vectors() + test_decode_known_vectors() + test_encode_roundtrip() + test_invalid_chars()
}

fn test_decode_known_vectors() -> Int {
  let f1 := match base32.decode("MY======") {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, bytes.from_str("f"))),
  }
  let f2 := match base32.decode("MFRA====") {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, bytes.from_str("fo"))),
  }
  let f3 := match base32.decode("MFRGG===") {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, bytes.from_str("foo"))),
  }
  let f4 := match base32.decode("MFRGGZA=") {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, bytes.from_str("foob"))),
  }
  let f5 := match base32.decode("MFRGGZDF") {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, bytes.from_str("fooba"))),
  }
  let f6 := match base32.decode("MFRGGZDFMY======") {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, bytes.from_str("foobar"))),
  }
  f1 + f2 + f3 + f4 + f5 + f6
}

fn test_encode_known_vectors() -> Int {
  chk(base32.encode(bytes.from_str("f")) == "MY======") + chk(base32.encode(bytes.from_str("fo")) == "MFRA====") + chk(base32.encode(bytes.from_str("foo")) == "MFRGG===") + chk(base32.encode(bytes.from_str("foob")) == "MFRGGZA=") + chk(base32.encode(bytes.from_str("fooba")) == "MFRGGZDF") + chk(base32.encode(bytes.from_str("foobar")) == "MFRGGZDFMY======") + chk(base32.encode(bytes.from_str("")) == "")
}

fn test_encode_roundtrip() -> Int {
  let data := bytes.from_str("Hello, world!")
  let enc := base32.encode(data)
  let f1 := match base32.decode(enc) {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, data)),
  }
  let data2 := bytes.from_str("The quick brown fox jumps over the lazy dog")
  let enc2 := base32.encode(data2)
  let f2 := match base32.decode(enc2) {
    Err(_) => 1,
    Ok(b) => chk(bytes.eq(b, data2)),
  }
  f1 + f2
}

fn test_invalid_chars() -> Int {
  match base32.decode("AAAA!AAA") {
    Ok(_) => 1,
    Err(_) => 0,
  }
}

