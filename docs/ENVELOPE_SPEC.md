# Ciphertext envelope v2 (AES-GCM)

Every value encrypted by cryptomigrate - and by any application that takes part in the migration - uses this self-describing format. It lets readers tell new ciphertext from legacy ciphertext without a lookup, carries the key id for rotation, and authenticates everything that matters. Implement it in any language with an AES-GCM primitive; the vector below is checked by `tests/test_crypto.py::test_documented_interoperability_vector`.

## Binary layout

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `89 43 4D 45` (`0x89` `C` `M` `E`) |
| 4 | 1 | version | `02` |
| 5 | 1 | algorithm | `01` = AES-128-GCM, `02` = AES-256-GCM |
| 6 | 1 | key-id length *L* | 1 … 64 |
| 7 | *L* | key id | ASCII `[A-Za-z0-9._:-]` |
| 7+*L* | 12 | nonce | 96-bit random IV (NIST SP 800-38D §8.2.2) |
| 19+*L* | *n*+16 | ciphertext ‖ tag | GCM output, 128-bit tag appended |

**Header** = bytes `0 … 7+L-1`. **Associated data (AAD)** = header ‖ `0x00` ‖ context.

The *context* is a caller-chosen byte string binding the ciphertext to where it lives; the default for database columns is `"{table}.{column}#{primary key}"` (UTF-8). Binding the header prevents algorithm or key-id substitution; binding the context prevents ciphertext from being moved between rows or columns. Use an empty context only when values are not location-specific (the default for files).

**Text armor** for VARCHAR/TEXT storage: `"$cm2$" + base64(envelope)` (standard alphabet, padded). `$` is outside the base64 and hex alphabets, so an armored value can never be mistaken for legacy base64/hex ciphertext.

## Rules

* Generate a fresh 12-byte nonce from a CSPRNG for **every** encryption; never reuse a nonce with the same key. With random nonces, stay below 2^32 encryptions per key (SP 800-38D §8.3); cryptomigrate counts usage and warns at 50 %.
* Reject unknown versions or algorithm ids. Treat any authentication failure as "decryption failed" without detail.
* A value that does not parse as an envelope is *legacy* during dual mode and *invalid* in strict mode.

## Decrypt (pseudo-code)

```
if len(blob) < 7 or blob[0:4] != 89 43 4D 45 or blob[4] != 2: not v2
alg   = blob[5]               # 1 or 2
L     = blob[6]               # 1..64
kid   = ascii(blob[7 : 7+L])
nonce = blob[7+L : 19+L]
body  = blob[19+L :]          # ciphertext || 16-byte tag
aad   = blob[0 : 7+L] || 0x00 || context
plaintext = AES-GCM-Decrypt(key(kid), nonce, body, aad)
```

## Java (JCA)

```java
static byte[] open(byte[] blob, byte[] context, java.util.function.Function<String, byte[]> keys) throws Exception {
    if (blob.length < 7 || (blob[0] & 0xff) != 0x89 || blob[1] != 'C' || blob[2] != 'M' || blob[3] != 'E' || blob[4] != 2)
        throw new IllegalArgumentException("not a v2 envelope");
    int headerLen = 7 + (blob[6] & 0xff);
    String keyId = new String(blob, 7, blob[6] & 0xff, java.nio.charset.StandardCharsets.US_ASCII);
    byte[] nonce = java.util.Arrays.copyOfRange(blob, headerLen, headerLen + 12);
    java.io.ByteArrayOutputStream aad = new java.io.ByteArrayOutputStream();
    aad.write(blob, 0, headerLen); aad.write(0); aad.write(context);
    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    c.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(keys.apply(keyId), "AES"),
           new javax.crypto.spec.GCMParameterSpec(128, nonce));
    c.updateAAD(aad.toByteArray());
    return c.doFinal(blob, headerLen + 12, blob.length - headerLen - 12);
}
```

Encryption mirrors this: build the header, draw a nonce with `SecureRandom`, `updateAAD(header || 0x00 || context)`, and emit `header || nonce || doFinal(plaintext)`.

## Interoperability vector

| Field | Value |
|---|---|
| key (32 bytes) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| key id | `aes256-20261002-a1b2c3` |
| nonce | `cafebabefacedbaddecaf888` |
| context | `customers.ssn_enc#42` (UTF-8) |
| plaintext | `123-45-6789` (UTF-8) |
| header | `89434d450202166165733235362d32303236313030322d613162326333` |
| AAD | header ‖ `00` ‖ `637573746f6d6572732e73736e5f656e63233432` |
| envelope | `89434d450202166165733235362d32303236313030322d613162326333cafebabefacedbaddecaf888bb91930b9e4f622d7133642dc86064e41e2cc2cf6a199cf23d4b10` |
| armored | `$cm2$iUNNRQICFmFlczI1Ni0yMDI2MTAwMi1hMWIyYzPK/rq++s7brd7K+Ii7kZMLnk9iLXEzZC3IYGTkHizCz2oZnPI9SxA=` |

(The fixed nonce exists only to make the vector reproducible. Never use a fixed nonce in production.)
