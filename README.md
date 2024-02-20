# assyst-nxcrypt

Assyst tags for advanced message encryption/decryption powered by WebAssembly.

## Algorithm

```
                                      [message]
                                          |
                                          v
                               (ISO/IEC 7816-4 padding)
                                          |
                                          v
[password] ----> (blake2b-256) ----> (ChaCha20) ----> [ciphertext]
                       ^                  ^
                       |                  |
                 (blake2b-256)      [random nonce]
                       ^
                       |
                  "Noxturnix"
```

# Credit

- [libsodium](https://libsodium.org) Copyright (c) 2013-2024 Frank Denis \<j at pureftpd dot org\>

# License

[ISC License](./LICENSE)
