import casper
import gleam/crypto
import gleeunit
import gleeunit/should

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn basic_roundtrip_no_associated_data_test() {
  let input = <<"casper test">>
  let key = casper.generate_key()

  let encrypted =
    casper.encrypt(input, key)
    |> should.be_ok

  let decrypted =
    casper.decrypt(encrypted, key)
    |> should.be_ok

  decrypted
  |> should.equal(input)
}

pub fn basic_roundtrip_with_associated_data_test() {
  let input = <<"casper test">>
  let associated = <<"casper associated">>
  let key = casper.generate_key()

  let encrypted =
    casper.encrypt_with(input, associated, key)
    |> should.be_ok

  let decrypted =
    casper.decrypt_with(encrypted, associated, key)
    |> should.be_ok

  decrypted
  |> should.equal(input)
}

pub fn fails_when_decrypt_associated_data_differs_test() {
  let input = <<"casper test">>
  let associated = <<"casper associated">>
  let key = casper.generate_key()

  let encrypted =
    casper.encrypt_with(input, associated, key)
    |> should.be_ok

  casper.decrypt_with(encrypted, <<"not this">>, key)
  |> should.be_error

  casper.decrypt(encrypted, key)
  |> should.be_error
}

pub fn fails_when_key_is_too_small_test() {
  let input = <<"casper test">>
  let key = crypto.strong_random_bytes(1)
  casper.encrypt(input, key)
  |> should.be_error
}

pub fn fails_when_key_is_too_large_test() {
  let input = <<"casper test">>
  let key = crypto.strong_random_bytes(33)
  casper.encrypt(input, key)
  |> should.be_error
}
