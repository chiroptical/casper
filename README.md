# casper

[![Package Version](https://img.shields.io/hexpm/v/casper)](https://hex.pm/packages/casper)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/casper/)

Casper is an opinionated symmetric cipher library which offers
[ChaCha20-Poly1305][chacha20-poly1305] via [Erlang][erlang-crypto] or
[Node][node-crypto].

Note: the `javascript` target will not work in a browser environment. The `bun`
and `deno` runtimes are not supported.
```sh
gleam add casper@2
```

```gleam
import casper

pub fn main() -> Nil {
  let key = casper.new_key()
  let encrypted = casper.encrypt(<<"casper">>, key)
  let assert Ok(decrypted) = casper.decrypt(encrypted, key)
  // ...
}
```

Further documentation can be found at <https://hexdocs.pm/casper>.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests on Erlang
gleam test -t javascript # Run the tests on Node
```

[chacha20-poly1305]: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
[erlang-crypto]: https://www.erlang.org/doc/apps/crypto/crypto.html
[node-crypto]: https://nodejs.org/api/crypto.html
