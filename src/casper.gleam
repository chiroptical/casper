//// An interface to the ChaCha20-Poly1305 symmetric cipher via Erlang and Node
//// libraries. The "with" variants allow you to add additional authenticated
//// data AAD which is required for encryption and decryption.

/// Generate 32 random bytes for use in the ChaCha20-Poly1305 cipher.
@external(erlang, "casper_ffi", "generate_key")
@external(javascript, "./casper_ffi.mjs", "generate_key")
pub fn generate_key() -> BitArray

@external(erlang, "casper_ffi", "encrypt_internal")
@external(javascript, "./casper_ffi.mjs", "encrypt_internal")
fn encrypt_internal(input: BitArray, key: BitArray) -> BitArray

@external(erlang, "casper_ffi", "encrypt_with_internal")
@external(javascript, "./casper_ffi.mjs", "encrypt_with_internal")
fn encrypt_with_internal(
  input: BitArray,
  associated_data: BitArray,
  key: BitArray,
) -> BitArray

@external(erlang, "casper_ffi", "decrypt_internal")
@external(javascript, "./casper_ffi.mjs", "decrypt_internal")
fn decrypt_internal(input: BitArray, key: BitArray) -> Result(BitArray, Nil)

@external(erlang, "casper_ffi", "decrypt_with_internal")
@external(javascript, "./casper_ffi.mjs", "decrypt_with_internal")
fn decrypt_with_internal(
  input: BitArray,
  associated_data: BitArray,
  key: BitArray,
) -> Result(BitArray, Nil)

/// Given a `BitArray` message and a 32 byte encryption key, generated via
/// `gleam/crypto` `strong_random_bytes` method, encrypt the input via
/// ChaCha20-Poly1305. The output `BitArray` is encoded especially for this
/// cipher.
///
/// This method will return `Error(Nil)` if you provide a non-32 byte key.
///
/// The javascript target uses Node's crypto library and will not work on the
/// web.
pub fn encrypt(
  message input: BitArray,
  key key: BitArray,
) -> Result(BitArray, Nil) {
  case key {
    <<encryption_key:bytes-size(32)>> -> {
      Ok(encrypt_internal(input, encryption_key))
    }
    _ -> Error(Nil)
  }
}

/// See `encrypt`. This method adds additional authenticated data to encrypt
/// the message.
pub fn encrypt_with(
  message input: BitArray,
  associated_data associated_data: BitArray,
  key key: BitArray,
) -> Result(BitArray, Nil) {
  case key {
    <<encryption_key:bytes-size(32)>> -> {
      Ok(encrypt_with_internal(input, associated_data, encryption_key))
    }
    _ -> Error(Nil)
  }
}

/// Given a `BitArray` message (the output from `encrypt`) and a 32 byte
/// encryption key attempt to decrypt the input.
///
/// This method will return `Error(Nil)` if it is unable to decrypt the input.
/// This will happen if you don't call `encrypt` first.
///
/// The javascript target uses Node's crypto library and will not work on the
/// web.
pub fn decrypt(
  message input: BitArray,
  key key: BitArray,
) -> Result(BitArray, Nil) {
  decrypt_internal(input, key)
}

/// See `decrypt`. This method adds additional authenticated data to decrypt
/// the message.
pub fn decrypt_with(
  message input: BitArray,
  associated_data associated_data: BitArray,
  key key: BitArray,
) -> Result(BitArray, Nil) {
  decrypt_with_internal(input, associated_data, key)
}
