# Getting started

[Back to documentation](README.md)

## Packages

| Package | Contents |
| --- | --- |
| `CryptoBase` | Algorithms and implementations; includes `CryptoBase.Abstractions`. |
| `CryptoBase.Abstractions` | Interfaces only, for libraries that take an algorithm as a type argument. |
| `CryptoBase.IO` | Stream and file helpers; depends only on `CryptoBase.Abstractions`, so add `CryptoBase` for the algorithms. |
| `CryptoBase.X509` | X.509 certificates; depends only on `CryptoBase.Abstractions`, so add `CryptoBase` for the algorithms. |

```shell
dotnet add package CryptoBase

# Optional.
dotnet add package CryptoBase.IO
dotnet add package CryptoBase.X509
```

## A first example

Hash a string and encrypt it:

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;

byte[] message = "hello world"u8.ToArray();

// SHA-256.
byte[] hash = new byte[HashAlgorithm<Sha256Core>.HashLength];
HashAlgorithm<Sha256Core>.HashData(message, hash);
Console.WriteLine(Convert.ToHexStringLower(hash));

// XChaCha20-Poly1305.
byte[] key = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.KeySize);
byte[] nonce = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.NonceSize);
byte[] ciphertext = new byte[message.Length];
byte[] tag = new byte[XChaCha20Poly1305Cipher.TagSize];

using XChaCha20Poly1305Cipher cipher = XChaCha20Poly1305Cipher.Create(key);
cipher.Encrypt(nonce, message, ciphertext, tag);
```

## Conventions

- Methods write into caller-supplied `Span<byte>` buffers. Static length properties, such as `HashLength`, `TagSize` or `SignatureLength`, give the size to allocate; a destination that is too short throws `ArgumentException`, except in `Base32Encoding`, which returns `OperationStatus`.
- Types that hold a key implement `IDisposable`, and disposing them erases the key.
- Static methods such as `HashData` and `Mac` handle one complete input. For input that arrives in pieces, `Create` an instance and call `Append`.
- Generic code can take any algorithm of a kind through the interfaces in `CryptoBase.Abstractions`, such as `IHashAlgorithm<TSelf>`, `IAeadCipher<TSelf>` or `IKem<TSelf>`.
