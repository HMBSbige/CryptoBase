# One-time passwords

[Back to documentation](README.md)

| Algorithm | Type | Namespace |
| --- | --- | --- |
| HOTP (RFC 4226) | `Hotp<TCore>` | `CryptoBase.Otp` |
| TOTP (RFC 6238) | `Totp<TCore>`, `TotpParameters` | `CryptoBase.Otp` |
| Steam Guard codes | `Totp<Sha1Core>` with `TotpParameters.SteamGuard` | `CryptoBase.Otp` |
| Code formats | `OtpCodeFormat` | `CryptoBase.Otp` |

`TCore` selects the HMAC hash, such as `Sha1Core`, `Sha256Core` or `Sha512Core`. A hash shorter than 20 bytes throws `NotSupportedException`.

## TOTP

```csharp
using System.Buffers;
using CryptoBase.Encodings;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Otp;

// The secret of an otpauth:// URI is unpadded Base32.
static byte[] DecodeSecret(string base32)
{
    byte[] key = new byte[Base32Encoding.GetMaxDecodedLength(base32.Length)];

    if (Base32Encoding.Rfc4648.OmitPadding.DecodeFromChars(base32, key, out _, out int written) is not OperationStatus.Done)
    {
        throw new FormatException("The secret is not valid Base32.");
    }

    return key.AsSpan(0, written).ToArray();
}

byte[] key = DecodeSecret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

// Six digits, a 30-second step and T0 = 0.
using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(key, TotpParameters.Rfc6238);

Span<char> code = stackalloc char[totp.Parameters.Format.Length];
totp.Generate(DateTimeOffset.UtcNow, code);
```

### Verifying a code

```csharp
using CryptoBase.Hashes.Sha1;
using CryptoBase.Otp;

static bool TryLogIn(Totp<Sha1Core> totp, ReadOnlySpan<char> code, ref long lastUsedStep)
{
    // Accept the current step and the one before it.
    if (!totp.Verify(DateTimeOffset.UtcNow, code, stepsBefore: 1, stepsAfter: 0, out long timeStep))
    {
        return false;
    }

    // Required: accept each step at most once. Check and store in one atomic step, so that concurrent
    // logins with the same code cannot both succeed; with a database, use one conditional update.
    long last = Volatile.Read(ref lastUsedStep);

    while (timeStep > last)
    {
        long seen = Interlocked.CompareExchange(ref lastUsedStep, timeStep, last);

        if (seen == last)
        {
            return true;
        }

        last = seen;
    }

    return false;
}
```

### Custom parameters

```csharp
using CryptoBase.Hashes.Sha2;
using CryptoBase.Otp;

byte[] key = new byte[32];

// HMAC-SHA-256, 8 digits, a 60-second step and steps counted from 2024-01-01T00:00:00Z.
// Decimal takes 6 to 9 digits.
TotpParameters parameters = new(OtpCodeFormat.Decimal(8), timeStepSeconds: 60, initialUnixTime: 1704067200);
using Totp<Sha256Core> totp = Totp<Sha256Core>.Create(key, parameters);

// floor((Unix time - T0) / X). Times before T0 throw ArgumentOutOfRangeException.
long step = parameters.GetTimeStep(DateTimeOffset.UtcNow);
```

### Steam Guard

```csharp
using CryptoBase.Hashes.Sha1;
using CryptoBase.Otp;

// The shared_secret of a Steam authenticator is standard Base64.
byte[] sharedSecret = Convert.FromBase64String("zvIayp3JPvtvX/QGHqsqKBk/44s=");

// TotpParameters.SteamGuard needs Sha1Core.
using Totp<Sha1Core> steam = Totp<Sha1Core>.Create(sharedSecret, TotpParameters.SteamGuard);

Span<char> code = stackalloc char[OtpCodeFormat.SteamGuard.Length];
steam.Generate(DateTimeOffset.FromUnixTimeSeconds(1616374841), code); // "2F9J5"
```

## HOTP

```csharp
using CryptoBase.Hashes.Sha1;
using CryptoBase.Otp;

byte[] key = "12345678901234567890"u8.ToArray();
using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(key, OtpCodeFormat.Decimal(6));

Span<char> code = stackalloc char[hotp.Format.Length];
hotp.Generate(counter: 0, code); // "755224"

static bool TryAccept(Hotp<Sha1Core> hotp, ReadOnlySpan<char> code, ref ulong nextCounter)
{
    ulong expected = Volatile.Read(ref nextCounter);

    // Accept the expected counter and up to 10 after it. Required: refuse the last counter,
    // which has no successor, so that the counter cannot wrap to 0 and accept old codes again.
    if (!hotp.Verify(expected, code, lookAhead: 10, out ulong matchedCounter) || matchedCounter == ulong.MaxValue)
    {
        return false;
    }

    // Required: move past the matched counter so that no code at or before it is accepted again,
    // and only if no concurrent login moved the counter since it was read.
    return Interlocked.CompareExchange(ref nextCounter, matchedCounter + 1, expected) == expected;
}
```
