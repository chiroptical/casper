//// An interface to the ChaCha20-Poly1305 symmetric cipher via Erlang and Node
//// libraries. The "with" variants allow you to add additional authenticated
//// data AAD which is required for encryption and decryption.

import gleam/bit_array
import gleam/io
import gleam/result

/// A 32 byte secret key. It is encoded as a thunk to avoid leaking the key
/// in logs.
pub opaque type SecretKey {
  SecretKey(fn() -> BitArray)
}

@external(erlang, "casper_ffi", "strong_random_bytes")
@external(javascript, "./casper_ffi.mjs", "strong_random_bytes")
fn strong_random_bytes(size: Int) -> BitArray

/// Generate a new `SecretKey`. This is only useful if you aren't persisting the
/// results of ciphers. See `from_bytes` for more details.
pub fn new_key() -> SecretKey {
  let key = strong_random_bytes(32)
  SecretKey(fn() { key })
}

/// Attempt to convert a `BitArray` into a `SecretKey`. This is useful when you
/// want to read an encryption key from your environment. For example, you could
/// store a base64 encoded secret as an environment variable. In the Erlang
/// shell, `base64:encode(crypto:strong_rand_bytes(32)).`
/// 
/// If you don't provide 32 bytes it will return `Error(Nil)`.
pub fn from_bytes(input: BitArray) -> Result(SecretKey, Nil) {
  case bit_array.byte_size(input) {
    32 -> Ok(SecretKey(fn() { input }))
    _ -> Error(Nil)
  }
}

/// Given a base64 encoded `String`, try to convert it to a valid `SecretKey`.
/// You are able to create one of these via `gleam run -m casper`.
pub fn from_base64(input: String) -> Result(SecretKey, Nil) {
  use decoded <- result.try(bit_array.base64_decode(input))
  from_bytes(decoded)
}

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

/// Given a `BitArray` message and a `SecretKey` encrypt the message via
/// ChaCha20-Poly1305. The output `BitArray` is encoded especially for this
/// cipher.
///
/// The javascript target uses Node's crypto library and will not work on the
/// web. Currently bun and deno runtimes are unsupported.
pub fn encrypt(message input: BitArray, key secret: SecretKey) -> BitArray {
  case secret {
    SecretKey(thunk) -> encrypt_internal(input, thunk())
  }
}

/// See `encrypt`. This method adds additional authenticated data to the message
/// for encryption.
pub fn encrypt_with(
  message input: BitArray,
  associated_data associated_data: BitArray,
  key secret: SecretKey,
) -> BitArray {
  case secret {
    SecretKey(thunk) -> encrypt_with_internal(input, associated_data, thunk())
  }
}

/// Given a `BitArray` (the output from `encrypt`) and a `SecretKey`
/// attempt to decrypt the message.
///
/// This method will return `Error(Nil)` if it is unable to decrypt the input.
/// This might happen if you don't call `encrypt` first.
///
/// The javascript target uses Node's crypto library and will not work on the
/// web. The bun and deno runtimes are not supported.
pub fn decrypt(
  message input: BitArray,
  key secret: SecretKey,
) -> Result(BitArray, Nil) {
  case secret {
    SecretKey(thunk) -> decrypt_internal(input, thunk())
  }
}

/// See `decrypt`. This method uses additional authenticated data to decrypt
/// the message.
pub fn decrypt_with(
  message input: BitArray,
  associated_data associated_data: BitArray,
  key secret: SecretKey,
) -> Result(BitArray, Nil) {
  case secret {
    SecretKey(thunk) -> decrypt_with_internal(input, associated_data, thunk())
  }
}

fn to_base64(secret: SecretKey) -> String {
  let SecretKey(thunk) = secret
  bit_array.base64_encode(thunk(), False)
}

pub fn main() {
  let key = new_key()
  io.println(to_base64(key))
}
