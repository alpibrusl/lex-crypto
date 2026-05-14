import "std.str" as str

import "std.bytes" as bytes

import "../src/oauth2" as oauth2

fn chk(cond :: Bool) -> Int {
  if cond {
    0
  } else {
    1
  }
}

fn fixed_entropy() -> Bytes {
  bytes.from_str("01234567890123456789012345678901")
}

fn run_all() -> Int {
  test_pkce_verify_roundtrip() + test_pkce_wrong_verifier() + test_pkce_verifier_length() + test_build_auth_url() + test_build_token_request_body() + test_url_encode()
}

fn test_pkce_verify_roundtrip() -> Int {
  let verifier := oauth2.pkce_verifier(fixed_entropy())
  let challenge := oauth2.pkce_challenge(verifier)
  chk(oauth2.pkce_verify(verifier, challenge))
}

fn test_pkce_wrong_verifier() -> Int {
  let verifier := oauth2.pkce_verifier(fixed_entropy())
  let challenge := oauth2.pkce_challenge(verifier)
  chk(not oauth2.pkce_verify("wrong-verifier-string", challenge))
}

fn test_pkce_verifier_length() -> Int {
  let verifier := oauth2.pkce_verifier(fixed_entropy())
  chk(str.len(verifier) == 43)
}

fn test_build_auth_url() -> Int {
  let verifier := oauth2.pkce_verifier(fixed_entropy())
  let challenge := oauth2.pkce_challenge(verifier)
  let state := oauth2.generate_state(bytes.from_str("1234567890123456"))
  let params := { client_id: "my_client", redirect_uri: "https://example.com/callback", scope: "openid profile", state: state, code_challenge: challenge }
  let url := oauth2.build_auth_url("https://auth.example.com/oauth/authorize", params)
  chk(str.starts_with(url, "https://auth.example.com/")) + chk(str.contains(url, "response_type=code")) + chk(str.contains(url, "client_id=my_client")) + chk(str.contains(url, "code_challenge_method=S256")) + chk(str.contains(url, "code_challenge=" + challenge))
}

fn test_build_token_request_body() -> Int {
  let req := { code: "auth_code_abc", redirect_uri: "https://example.com/callback", client_id: "my_client", code_verifier: "my_verifier_string" }
  let body := oauth2.build_token_request_body(req)
  chk(str.contains(body, "grant_type=authorization_code")) + chk(str.contains(body, "code=auth_code_abc")) + chk(str.contains(body, "code_verifier=my_verifier_string"))
}

fn test_url_encode() -> Int {
  chk(oauth2.url_encode("hello world") == "hello+world") + chk(oauth2.url_encode("a=b&c=d") == "a%3Db%26c%3Dd") + chk(oauth2.url_encode("abc123-_.") == "abc123-_.") + chk(oauth2.url_encode("user@host") == "user%40host")
}

