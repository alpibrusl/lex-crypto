import "std.crypto" as crypto

import "std.str" as str

import "std.bytes" as bytes

fn hex_digit(c :: Str) -> Int
  examples {
    hex_digit("0") => 0,
    hex_digit("9") => 9,
    hex_digit("a") => 10,
    hex_digit("f") => 15
  }
{
  match c {
    "0" => 0,
    "1" => 1,
    "2" => 2,
    "3" => 3,
    "4" => 4,
    "5" => 5,
    "6" => 6,
    "7" => 7,
    "8" => 8,
    "9" => 9,
    "a" => 10,
    "b" => 11,
    "c" => 12,
    "d" => 13,
    "e" => 14,
    _ => 15,
  }
}

fn byte_at(b :: Bytes, idx :: Int) -> Int {
  let single := bytes.slice(b, idx, idx + 1)
  let hex := crypto.hex_encode(single)
  hex_digit(str.slice(hex, 0, 1)) * 16 + hex_digit(str.slice(hex, 1, 2))
}

fn int_to_hex_char(n :: Int) -> Str
  examples {
    int_to_hex_char(0) => "0",
    int_to_hex_char(9) => "9",
    int_to_hex_char(10) => "a",
    int_to_hex_char(15) => "f"
  }
{
  str.slice("0123456789abcdef", n, n + 1)
}

fn byte_to_hex(b :: Int) -> Str
  examples {
    byte_to_hex(0) => "00",
    byte_to_hex(16) => "10",
    byte_to_hex(255) => "ff"
  }
{
  int_to_hex_char(b / 16) + int_to_hex_char(b % 16)
}

fn int_to_hex16(n :: Int) -> Str
  examples {
    int_to_hex16(0) => "0000000000000000",
    int_to_hex16(255) => "00000000000000ff"
  }
{
  byte_to_hex(n / 72057594037927936 % 256) + byte_to_hex(n / 281474976710656 % 256) + byte_to_hex(n / 1099511627776 % 256) + byte_to_hex(n / 4294967296 % 256) + byte_to_hex(n / 16777216 % 256) + byte_to_hex(n / 65536 % 256) + byte_to_hex(n / 256 % 256) + byte_to_hex(n % 256)
}

fn pad_left(s :: Str, width :: Int, ch :: Str) -> Str
  examples {
    pad_left("42", 6, "0") => "000042",
    pad_left("hello", 3, "0") => "hello"
  }
{
  if str.len(s) >= width {
    s
  } else {
    pad_left(ch + s, width, ch)
  }
}

fn json_escape(s :: Str) -> Str
  examples {
    json_escape("hello") => "hello",
    json_escape("say \"hi\"") => "say \\\"hi\\\""
  }
{
  let s1 := str.replace(s, "\\", "\\\\")
  let s2 := str.replace(s1, "\"", "\\\"")
  let s3 := str.replace(s2, "\n", "\\n")
  let s4 := str.replace(s3, "\r", "\\r")
  str.replace(s4, "\t", "\\t")
}

