import "std.str" as str

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.int" as int

import "std.list" as list

import "std.map" as map

fn pkce_verifier(entropy :: Bytes) -> Str {
  crypto.base64url_encode(entropy)
}

fn pkce_challenge(verifier :: Str) -> Str {
  crypto.base64url_encode(crypto.sha256(bytes.from_str(verifier)))
}

fn pkce_verify(verifier :: Str, challenge :: Str) -> Bool {
  let expected := pkce_challenge(verifier)
  crypto.eq_str(expected, challenge)
}

type AuthParams = { client_id :: Str, redirect_uri :: Str, scope :: Str, state :: Str, code_challenge :: Str }

fn build_auth_url(base_url :: Str, params :: AuthParams) -> Str {
  base_url + "?response_type=code" + "&client_id=" + url_encode(params.client_id) + "&redirect_uri=" + url_encode(params.redirect_uri) + "&scope=" + url_encode(params.scope) + "&state=" + url_encode(params.state) + "&code_challenge=" + params.code_challenge + "&code_challenge_method=S256"
}

fn generate_state(entropy :: Bytes) -> Str {
  crypto.hex_encode(entropy)
}

type TokenRequest = { code :: Str, redirect_uri :: Str, client_id :: Str, code_verifier :: Str }

fn build_token_request_body(req :: TokenRequest) -> Str {
  "grant_type=authorization_code" + "&code=" + url_encode(req.code) + "&redirect_uri=" + url_encode(req.redirect_uri) + "&client_id=" + url_encode(req.client_id) + "&code_verifier=" + url_encode(req.code_verifier)
}

fn url_encode(s :: Str) -> Str {
  url_encode_chars(s, 0, str.len(s), "")
}

fn url_encode_chars(s :: Str, pos :: Int, len :: Int, acc :: Str) -> Str {
  if pos >= len {
    acc
  } else {
    let c := str.slice(s, pos, pos + 1)
    url_encode_chars(s, pos + 1, len, acc + url_encode_char(c))
  }
}

fn url_encode_char(c :: Str) -> Str {
  match c {
    "A" => "A",
    "B" => "B",
    "C" => "C",
    "D" => "D",
    "E" => "E",
    "F" => "F",
    "G" => "G",
    "H" => "H",
    "I" => "I",
    "J" => "J",
    "K" => "K",
    "L" => "L",
    "M" => "M",
    "N" => "N",
    "O" => "O",
    "P" => "P",
    "Q" => "Q",
    "R" => "R",
    "S" => "S",
    "T" => "T",
    "U" => "U",
    "V" => "V",
    "W" => "W",
    "X" => "X",
    "Y" => "Y",
    "Z" => "Z",
    "a" => "a",
    "b" => "b",
    "c" => "c",
    "d" => "d",
    "e" => "e",
    "f" => "f",
    "g" => "g",
    "h" => "h",
    "i" => "i",
    "j" => "j",
    "k" => "k",
    "l" => "l",
    "m" => "m",
    "n" => "n",
    "o" => "o",
    "p" => "p",
    "q" => "q",
    "r" => "r",
    "s" => "s",
    "t" => "t",
    "u" => "u",
    "v" => "v",
    "w" => "w",
    "x" => "x",
    "y" => "y",
    "z" => "z",
    "0" => "0",
    "1" => "1",
    "2" => "2",
    "3" => "3",
    "4" => "4",
    "5" => "5",
    "6" => "6",
    "7" => "7",
    "8" => "8",
    "9" => "9",
    "-" => "-",
    "_" => "_",
    "." => ".",
    "~" => "~",
    " " => "+",
    "@" => "%40",
    ":" => "%3A",
    "/" => "%2F",
    "?" => "%3F",
    "=" => "%3D",
    "&" => "%26",
    "+" => "%2B",
    "#" => "%23",
    "!" => "%21",
    "$" => "%24",
    "," => "%2C",
    ";" => "%3B",
    "[" => "%5B",
    "]" => "%5D",
    _ => c,
  }
}

