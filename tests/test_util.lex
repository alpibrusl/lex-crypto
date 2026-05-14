import "std.str" as str

import "../src/util" as util

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn run_all() -> Int {
  test_hex_digit() + test_byte_to_hex() + test_int_to_hex16() + test_pad_left() + test_json_escape()
}

fn test_hex_digit() -> Int {
  chk(util.hex_digit("0") == 0) + chk(util.hex_digit("9") == 9) + chk(util.hex_digit("a") == 10) + chk(util.hex_digit("f") == 15)
}

fn test_byte_to_hex() -> Int {
  chk(util.byte_to_hex(0) == "00") + chk(util.byte_to_hex(15) == "0f") + chk(util.byte_to_hex(16) == "10") + chk(util.byte_to_hex(255) == "ff") + chk(util.byte_to_hex(171) == "ab")
}

fn test_int_to_hex16() -> Int {
  chk(util.int_to_hex16(0) == "0000000000000000") + chk(util.int_to_hex16(1) == "0000000000000001") + chk(util.int_to_hex16(255) == "00000000000000ff") + chk(util.int_to_hex16(256) == "0000000000000100") + chk(str.len(util.int_to_hex16(12345678)) == 16)
}

fn test_pad_left() -> Int {
  chk(util.pad_left("42", 6, "0") == "000042") + chk(util.pad_left("hello", 3, "0") == "hello") + chk(util.pad_left("", 4, "x") == "xxxx") + chk(util.pad_left("ab", 2, "0") == "ab")
}

fn test_json_escape() -> Int {
  chk(util.json_escape("hello") == "hello") + chk(util.json_escape("a\\b") == "a\\\\b") + chk(util.json_escape("line1\nline2") == "line1\\nline2")
}

