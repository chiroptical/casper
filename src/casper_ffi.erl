-module(casper_ffi).

-export([
    generate_key/0,
    encrypt_internal/2,
    decrypt_internal/2,
    encrypt_with_internal/3,
    decrypt_with_internal/3
]).

generate_key() ->
    crypto:strong_rand_bytes(32).

encrypt_internal(Value, Key) ->
    Iv = crypto:strong_rand_bytes(12),
    {Encrypted, Tag} = crypto:crypto_one_time_aead(
        chacha20_poly1305, Key, Iv, Value, <<>>, true
    ),
    <<Iv/binary, Tag/binary, Encrypted/binary>>.

decrypt_internal(<<Iv:12/binary, Tag:16/binary, Encrypted/binary>>, Key) ->
    Decrypted = crypto:crypto_one_time_aead(
        chacha20_poly1305, Key, Iv, Encrypted, <<>>, Tag, false
    ),
    case Decrypted of
        {_, _} -> {error, nil};
        error -> {error, nil};
        {error, _, _} -> {error, nil};
        Decrypt -> {ok, Decrypt}
    end.

encrypt_with_internal(Value, AssociatedData, Key) ->
    Iv = crypto:strong_rand_bytes(12),
    {Encrypted, Tag} = crypto:crypto_one_time_aead(
        chacha20_poly1305, Key, Iv, Value, AssociatedData, true
    ),
    <<Iv/binary, Tag/binary, Encrypted/binary>>.

decrypt_with_internal(<<Iv:12/binary, Tag:16/binary, Encrypted/binary>>, AssociatedData, Key) ->
    Decrypted = crypto:crypto_one_time_aead(
        chacha20_poly1305, Key, Iv, Encrypted, AssociatedData, Tag, false
    ),
    case Decrypted of
        {_, _} -> {error, nil};
        error -> {error, nil};
        {error, _, _} -> {error, nil};
        Decrypt -> {ok, Decrypt}
    end.
