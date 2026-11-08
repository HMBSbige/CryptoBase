using CryptoBase.EllipticCurves;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.SM2;
using CryptoBase.Tests.EllipticCurves;
using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Numerics;
using System.Reflection;

namespace CryptoBase.Tests.SM2;

internal static class SM2TestUtils
{
	public static CurveCase Curve { get; } = CurveCase.Named(CurveCase.SM2Name);

	public static ECReference Reference => Curve.Reference;

	public static BigInteger N => Reference.N;

	public static byte[] Hex(string hex)
	{
		return Convert.FromHexString(hex.Replace(" ", "", StringComparison.Ordinal));
	}

	public static BigInteger Integer(string hex)
	{
		return ModulusCase.Decode(Hex(hex));
	}

	public static byte[] Encode(BigInteger value)
	{
		return CurveCase.EncodeInteger(value, 32);
	}

	public static byte[] EncodePoint(CurvePoint point)
	{
		return Curve.EncodePoint(point);
	}

	// Gives each value in turn, as the randomness of a key, nonce or ephemeral key that a test chooses, and fails once they run out.
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

	// Z of GB/T 32918.2-2016, Sec. 5.5, from the curve parameters of the reference.
	public static byte[] ReferenceZ(ReadOnlySpan<byte> id, CurvePoint publicKey)
	{
		byte[] length = new byte[2];
		BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)(8 * id.Length));
		ECReference reference = Reference;
		return Sm3(length, id.ToArray(), Encode(reference.A), Encode(reference.B), Encode(reference.Generator.X), Encode(reference.Generator.Y), Encode(publicKey.X), Encode(publicKey.Y));
	}

	// KDF of GB/T 32918.4-2016, Sec. 5.4.3.
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

	// GB/T 32918.2-2016, Sec. 7.1, from the reference: r and s in [1, n − 1], t = r + s ≠ 0 and (e + x1') mod n = r for (x1', y1') = s·G + t·P.
	public static bool ReferenceVerify(CurvePoint publicKey, ReadOnlySpan<byte> id, byte[] message, BigInteger r, BigInteger s)
	{
		if (r < 1 || r >= N || s < 1 || s >= N || (r + s) % N == 0)
		{
			return false;
		}

		BigInteger e = ModulusCase.Decode(Sm3(ReferenceZ(id, publicKey), message));
		CurvePoint? point = Reference.Add(Reference.Multiply(Reference.Generator, s), Reference.Multiply(publicKey, (r + s) % N));
		return point is not null && (e + point.X) % N == r;
	}

	// GB/T 32918.4-2016, Sec. 6.1, from the reference, for a k whose key stream is not all zero.
	public static byte[] ReferenceEncrypt(CurvePoint publicKey, byte[] plaintext, BigInteger k)
	{
		CurvePoint c1 = Reference.PublicKey(k);
		CurvePoint shared = Reference.Multiply(publicKey, k) ?? throw new ArgumentOutOfRangeException(nameof(k));
		byte[] t = ReferenceKdf([.. Encode(shared.X), .. Encode(shared.Y)], plaintext.Length);

		if (!t.AsSpan().ContainsAnyExcept((byte)0))
		{
			throw new ArgumentOutOfRangeException(nameof(k), k, "The key stream is all zero.");
		}

		return [.. EncodePoint(c1), .. Sm3(Encode(shared.X), plaintext, Encode(shared.Y)), .. plaintext.Zip(t, static (m, key) => (byte)(m ^ key))];
	}

	// GB/T 32918.4-2016, Sec. 7.1, from the reference: the plaintext, or null.
	public static byte[]? ReferenceDecrypt(BigInteger privateKey, byte[] ciphertext)
	{
		if (ciphertext.Length <= 97 || ciphertext[0] is not 0x04)
		{
			return null;
		}

		CurvePoint c1 = Curve.DecodePoint(ciphertext.AsSpan(0, 65));

		if (!Reference.IsOnCurve(c1))
		{
			return null;
		}

		CurvePoint shared = Reference.Multiply(c1, privateKey)!;
		byte[] c2 = ciphertext.AsSpan(97).ToArray();
		byte[] t = ReferenceKdf([.. Encode(shared.X), .. Encode(shared.Y)], c2.Length);
		byte[] plaintext = [.. c2.Zip(t, static (c, key) => (byte)(c ^ key))];
		return t.AsSpan().ContainsAnyExcept((byte)0) && Sm3(Encode(shared.X), plaintext, Encode(shared.Y)).AsSpan().SequenceEqual(ciphertext.AsSpan(65, 32)) ? plaintext : null;
	}

	public static byte[] DerSignature(BigInteger r, BigInteger s)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteInteger(r);
			writer.WriteInteger(s);
		}

		return writer.Encode();
	}

	// The SM2Cipher of GB/T 35276-2017, written here rather than by the code under test.
	public static byte[] DerCiphertext(BigInteger x, BigInteger y, byte[] hash, byte[] cipherText)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteInteger(x);
			writer.WriteInteger(y);
			writer.WriteOctetString(hash);
			writer.WriteOctetString(cipherText);
		}

		return writer.Encode();
	}

	public static byte[] Sign(SM2Key key, byte[] message, byte[]? id = null)
	{
		byte[] signature = new byte[SM2Key.MaxSignatureLength];
		int written = id is null ? key.Sign(message, signature) : key.Sign(message, signature, id);
		return signature.AsSpan(0, written).ToArray();
	}

	public static byte[] Encrypt(SM2Key key, byte[] plaintext)
	{
		byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(plaintext.Length)];
		_ = key.Encrypt(plaintext, ciphertext);
		return ciphertext;
	}

	public static byte[] EncryptDer(SM2Key key, byte[] plaintext)
	{
		byte[] ciphertext = new byte[SM2Key.GetMaxDerCiphertextLength(plaintext.Length)];
		int written = key.EncryptDer(plaintext, ciphertext);
		return ciphertext.AsSpan(0, written).ToArray();
	}

	// The plaintext, or null where decryption fails.
	public static byte[]? Decrypt(SM2Key key, byte[] ciphertext)
	{
		byte[] plaintext = new byte[ciphertext.Length];
		return key.TryDecrypt(ciphertext, plaintext, out int written) ? plaintext.AsSpan(0, written).ToArray() : null;
	}

	public static byte[]? DecryptDer(SM2Key key, byte[] ciphertext)
	{
		byte[] plaintext = new byte[ciphertext.Length];
		return key.TryDecryptDer(ciphertext, plaintext, out int written) ? plaintext.AsSpan(0, written).ToArray() : null;
	}

	public static FieldElement<SM2Order> Scalar(BigInteger value)
	{
		if (!FieldElement<SM2Order>.TryImport(Encode(value), out FieldElement<SM2Order> scalar))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The scalar is not below n.");
		}

		return scalar;
	}

	public static BigInteger Value(in FieldElement<SM2Order> scalar)
	{
		byte[] bytes = new byte[32];
		FieldElement<SM2Order>.Export(in scalar, bytes);
		return ModulusCase.Decode(bytes);
	}

	// The operation of SM2KeyState that builds the windows of the public key, from the constant of that name.
	public static int TableThreshold(string name)
	{
		return (int)typeof(SM2KeyState).GetField(name, BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
	}

	// Whether the key holds the windows of its public key for encryption and key exchange.
	public static bool HasTable(SM2Key key)
	{
		object state = typeof(SM2Key).GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(key)!;
		return typeof(SM2KeyState).GetField("_table", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(state) is not null;
	}

	// Whether the key holds the windows of its public key for verification, those of SM2VerificationCurve.
	public static bool HasVerificationTable(SM2Key key)
	{
		object state = typeof(SM2Key).GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(key)!;
		return typeof(SM2KeyState).GetField("_verificationTable", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(state) is not null;
	}

	// The stage of (1 + d)⁻¹ in the state of the key, and the value that the state holds for it, plain: (1 + d)⁻¹·R mod n once it is ready, 0 before. They are read through reflection, so also after disposal.
	public static (int Stage, BigInteger Inverse) InverseOf(SM2Key key)
	{
		object state = typeof(SM2Key).GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(key)!;
		int stage = (int)typeof(SM2KeyState).GetField("_inverseStage", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(state)!;
		FieldElement<SM2Order> inverse = (FieldElement<SM2Order>)typeof(SM2KeyState).GetField("_inverse", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(state)!;
		return (stage, Value(in inverse));
	}

	// Sets the stage of (1 + d)⁻¹ in the state of the key, in place.
	public static void SetInverseStage(SM2Key key, int stage)
	{
		ref SM2KeyState state = ref key.GetState();
		typeof(SM2KeyState).GetField("_inverseStage", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValueDirect(__makeref(state), stage);
	}

	// The constant of SM2KeyState for a stage of (1 + d)⁻¹.
	public static int InverseStage(string name)
	{
		return (int)typeof(SM2KeyState).GetField(name, BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
	}
}
