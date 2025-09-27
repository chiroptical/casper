@external(erlang, "casper_ffi", "encrypt_internal")
fn encrypt_internal(input: BitArray, key: BitArray) -> BitArray

@external(erlang, "casper_ffi", "encrypt_with_internal")
fn encrypt_with_internal(
  input: BitArray,
  associated_data: BitArray,
  key: BitArray,
) -> BitArray

@external(erlang, "casper_ffi", "decrypt_internal")
fn decrypt_internal(input: BitArray, key: BitArray) -> Result(BitArray, Nil)

@external(erlang, "casper_ffi", "decrypt_with_internal")
fn decrypt_with_internal(
  input: BitArray,
  associated_data: BitArray,
  key: BitArray,
) -> Result(BitArray, Nil)

pub fn encrypt(input: BitArray, key: BitArray) -> Result(BitArray, Nil) {
  case key {
    <<encryption_key:bytes-size(32)>> -> {
      Ok(encrypt_internal(input, encryption_key))
    }
    _ -> Error(Nil)
  }
}

pub fn encrypt_with(
  input: BitArray,
  associated_data: BitArray,
  key: BitArray,
) -> Result(BitArray, Nil) {
  case key {
    <<encryption_key:bytes-size(32)>> -> {
      Ok(encrypt_with_internal(input, associated_data, encryption_key))
    }
    _ -> Error(Nil)
  }
}

pub fn decrypt(input: BitArray, key: BitArray) -> Result(BitArray, Nil) {
  decrypt_internal(input, key)
}

pub fn decrypt_with(
  input: BitArray,
  associated_data: BitArray,
  key: BitArray,
) -> Result(BitArray, Nil) {
  decrypt_with_internal(input, associated_data, key)
}
