Changelog
---

v2.1.0
===

- Added the ability to run `gleam run -m casper` and generate a base64 encoded secret for use in an environment variable
- Added `casper.from_base64(String) -> Result(SecretKey, Nil)` to read an environment variable with a base64 encoded secret

v2.0.1
===

- Handle failure when decrypting message that doesn't match encoding format
