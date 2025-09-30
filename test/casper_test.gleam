import casper
import gleeunit
import gleeunit/should

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn basic_roundtrip_no_associated_data_test() {
  let input = <<"casper test">>
  let key = casper.new_key()

  let encrypted = casper.encrypt(input, key)

  let decrypted =
    casper.decrypt(encrypted, key)
    |> should.be_ok

  decrypted
  |> should.equal(input)
}

pub fn basic_roundtrip_with_associated_data_test() {
  let input = <<"casper test">>
  let associated = <<"casper associated">>
  let key = casper.new_key()

  let encrypted = casper.encrypt_with(input, associated, key)

  let decrypted =
    casper.decrypt_with(encrypted, associated, key)
    |> should.be_ok

  decrypted
  |> should.equal(input)
}

pub fn fails_when_decrypt_associated_data_differs_test() {
  let input = <<"casper test">>
  let associated = <<"casper associated">>
  let key = casper.new_key()

  let encrypted = casper.encrypt_with(input, associated, key)

  casper.decrypt_with(encrypted, <<"not this">>, key)
  |> should.be_error

  casper.decrypt(encrypted, key)
  |> should.be_error
}

pub fn fails_to_decrypt_improper_message_test() {
  let input = <<>>
  let key = casper.new_key()
  casper.decrypt(input, key)
  |> should.be_error
}

pub fn fails_when_key_is_too_small_test() {
  casper.from_bytes(<<"1">>)
  |> should.be_error
}

pub fn fails_when_key_is_too_large_test() {
  <<"1234567891011121314151617181920">>
  |> casper.from_bytes
  |> should.be_error
}
