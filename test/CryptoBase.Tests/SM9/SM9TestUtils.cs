using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.SM9;
using CryptoBase.Tests.EllipticCurves.SM9;
using System.Buffers.Binary;
using System.Numerics;
using SM9EllipticCurveTestUtils = CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;

namespace CryptoBase.Tests.SM9;

internal static class SM9TestUtils
{
	public static byte[] Hex(string hex)
	{
		return Convert.FromHexString(hex.Replace(" ", "", StringComparison.Ordinal));
	}

	// The 32 big-endian bytes of a value printed in hex, which may be shorter.
	public static byte[] Scalar(string hex)
	{
		return SM9Reference.Encode(SM9Reference.Parse(hex));
	}

	// Gives each value in turn, as the randomness of a key or ephemeral key that a test chooses, and fails once they run out.
	public static Action<Span<byte>> Fill(params byte[][] values)
	{
		int next = 0;
		return destination =>
		{
			if (next >= values.Length)
			{
				throw new InvalidOperationException("The test ran out of randomness.");
			}

			values[next++].CopyTo(destination);
		};
	}

	public static byte[] Sm3(params byte[][] parts)
	{
		byte[] hash = new byte[32];
		_ = HashAlgorithm<SM3Core>.HashData([.. parts.SelectMany(static part => part)], hash);
		return hash;
	}

	// The KDF of GM/T 0044.3-2016, Sec. 5.4.3.
	public static byte[] ReferenceKdf(byte[] z, int length)
	{
		List<byte> key = [];

		for (uint counter = 1; key.Count < length; ++counter)
		{
			byte[] encodedCounter = new byte[4];
			BinaryPrimitives.WriteUInt32BigEndian(encodedCounter, counter);
			key.AddRange(Sm3(z, encodedCounter));
		}

		return [.. key.Take(length)];
	}

	// H1 or H2 of GM/T 0044.2-2016, Sec. 5.4.2, with hlen = 320 bits.
	public static BigInteger ReferenceHash(byte prefix, byte[] z)
	{
		byte[] ha = ReferenceKdf([prefix, .. z], 40);
		return new BigInteger(ha, true, true) % (SM9Reference.N - 1) + 1;
	}

	// A scalar in [1, N − 1].
	public static BigInteger RandomScalar(Random random)
	{
		return SM9EllipticCurveTestUtils.RandomBelow(random, SM9Reference.N - 1) + 1;
	}

	// 04 ‖ x ‖ y, with each coordinate a1 ‖ a0.
	public static byte[] EncodePoint(G2Value point)
	{
		return [0x04, .. SM9Reference.Encode(point.X.A1), .. SM9Reference.Encode(point.X.A0), .. SM9Reference.Encode(point.Y.A1), .. SM9Reference.Encode(point.Y.A0)];
	}

	public static byte[] EncodePoint(G1Value point)
	{
		return [0x04, .. SM9Reference.Encode(point.X), .. SM9Reference.Encode(point.Y)];
	}

	// A point of the twist E'(Fp2) outside G2, as almost all of its points are, whose order N·(2p − N) has a cofactor of 256 bits.
	public static byte[] EncodeTwistPointOutsideG2()
	{
		for (int x = 1; ; ++x)
		{
			if (SM9Reference.TwistPoint(new Fp2Value(x, 1)) is { } point && SM9Reference.Multiply(point, SM9Reference.N) is not null)
			{
				return EncodePoint(point);
			}
		}
	}

	public static bool IsZero(in SM9AffinePoint<SM9Fp> point)
	{
		return SM9EllipticCurveTestUtils.RawValue(point.X).IsZero && SM9EllipticCurveTestUtils.RawValue(point.Y).IsZero;
	}

	public static bool IsZero(in SM9AffinePoint<SM9Fp2> point)
	{
		return ((BigInteger[])[SM9EllipticCurveTestUtils.RawValue(point.X.A0), SM9EllipticCurveTestUtils.RawValue(point.X.A1), SM9EllipticCurveTestUtils.RawValue(point.Y.A0), SM9EllipticCurveTestUtils.RawValue(point.Y.A1)]).All(static value => value.IsZero);
	}

	public static byte[] ExportPublicKey(SM9SignatureMasterKey key)
	{
		byte[] publicKey = new byte[SM9SignatureMasterKey.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	public static byte[] ExportPublicKey(SM9EncryptionMasterKey key)
	{
		byte[] publicKey = new byte[SM9EncryptionMasterKey.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	public static byte[] ExportPrivateKey(SM9SignatureKey key)
	{
		byte[] privateKey = new byte[SM9SignatureKey.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPrivateKey(SM9EncryptionKey key)
	{
		byte[] privateKey = new byte[SM9EncryptionKey.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPrivateKey(SM9KeyExchangeKey key)
	{
		byte[] privateKey = new byte[SM9KeyExchangeKey.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] Sign(SM9SignatureKey key, byte[] message)
	{
		byte[] signature = new byte[SM9SignatureKey.SignatureLength];
		_ = key.Sign(message, signature);
		return signature;
	}

	public static byte[] SignDer(SM9SignatureKey key, byte[] message)
	{
		byte[] signature = new byte[SM9SignatureKey.DerSignatureLength];
		_ = key.SignDer(message, signature);
		return signature;
	}

	public static byte[] Encrypt(SM9EncryptionMasterKey key, byte[] plaintext, byte[] id)
	{
		byte[] ciphertext = new byte[SM9EncryptionMasterKey.GetCiphertextLength(plaintext.Length)];
		_ = key.Encrypt(plaintext, ciphertext, id);
		return ciphertext;
	}

	public static byte[] EncryptDer(SM9EncryptionMasterKey key, byte[] plaintext, byte[] id)
	{
		byte[] ciphertext = new byte[SM9EncryptionMasterKey.GetDerCiphertextLength(plaintext.Length)];
		_ = key.EncryptDer(plaintext, ciphertext, id);
		return ciphertext;
	}

	// The plaintext, or null where decryption fails.
	public static byte[]? Decrypt(SM9EncryptionKey key, byte[] ciphertext)
	{
		byte[] plaintext = new byte[ciphertext.Length];
		return key.TryDecrypt(ciphertext, plaintext, out int written) ? plaintext.AsSpan(0, written).ToArray() : null;
	}

	public static byte[]? DecryptDer(SM9EncryptionKey key, byte[] ciphertext)
	{
		byte[] plaintext = new byte[ciphertext.Length];
		return key.TryDecryptDer(ciphertext, plaintext, out int written) ? plaintext.AsSpan(0, written).ToArray() : null;
	}

	// The key, or null where decapsulation fails.
	public static byte[]? Decapsulate(SM9EncryptionKey key, byte[] encapsulation, int length)
	{
		byte[] sharedKey = new byte[length];
		return key.TryDecapsulate(encapsulation, sharedKey) ? sharedKey : null;
	}

	// Whether the import of a user private key rejects it with the ArgumentException for privateKey, as for a key of another ID, master key or hid.
	public static bool ImportThrows(Func<IDisposable> import)
	{
		try
		{
			using IDisposable _ = import();
			return false;
		}
		catch (ArgumentException e) when (e.ParamName is "privateKey")
		{
			return true;
		}
	}

	public static byte[] ExportEphemeral(SM9KeyExchange exchange)
	{
		byte[] ephemeral = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
		exchange.ExportEphemeralPublicKey(ephemeral);
		return ephemeral;
	}
}
