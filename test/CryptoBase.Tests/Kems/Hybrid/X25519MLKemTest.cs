using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using CryptoBase.KeyAgreements.Xdh;
using CryptoBase.Tests.Kems.MLKem;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.Kems.Hybrid.ECMLKemTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.KeyAgreements.Xdh.X25519TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems.Hybrid;

// X25519MLKem768 against MLKem768 and X25519, with the ML-KEM part first everywhere, as RFC 10024 orders X25519MLKEM768.
public class X25519MLKemTest
{
	private const int Iterations = 4;

	private static int MLKemEncapsulationKeyLength => MLKem768.EncapsulationKeyLength;

	private static int MLKemCiphertextLength => MLKem768.CiphertextLength;

	[Test]
	public async Task LengthsAreFixed()
	{
		await Assert.That((X25519MLKem768.EncapsulationKeyLength, X25519MLKem768.CiphertextLength, X25519MLKem768.SharedSecretLength, X25519MLKem768.PrivateSeedLength, X25519MLKem768.DecapsulationKeyLength)).IsEqualTo((1216, 1120, 64, 96, 2432));
	}

	[Test]
	public async Task KeysConcatenateTheirParts()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		(byte[] mlKemSeed, byte[] privateKey) = Split(ExportPrivateSeed(kem), MLKem768.PrivateSeedLength);
		using MLKem768 mlKem = MLKem768.ImportPrivateSeed(mlKemSeed);
		using X25519 x25519 = X25519.ImportPrivateKey(privateKey);

		using (Assert.Multiple())
		{
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(Concat(ExportEncapsulationKey(mlKem), ExportPublicKey(x25519)), CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(kem)).IsEquivalentTo(Concat(ExportDecapsulationKey(mlKem), privateKey), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task EncapsulationConcatenatesItsParts()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		(byte[] mlKemEncapsulationKey, byte[] publicKey) = Split(ExportEncapsulationKey(kem), MLKemEncapsulationKeyLength);
		using X25519 staticKey = X25519.ImportPrivateKey(ExportPrivateSeed(kem).AsSpan(MLKem768.PrivateSeedLength));
		using MLKem768 mlKem = MLKem768.ImportEncapsulationKey(mlKemEncapsulationKey);
		byte[][] ephemeralPrivateKeys = [new byte[32], Enumerable.Repeat((byte)0xFF, 32).ToArray(), RandomNumberGenerator.GetBytes(32)];

		foreach (byte[] ephemeralPrivateKey in ephemeralPrivateKeys)
		{
			byte[] message = RandomNumberGenerator.GetBytes(32);
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem, ephemeralPrivateKey, message);
			using X25519 ephemeral = X25519.ImportPrivateKey(ephemeralPrivateKey);
			byte[] ephemeralPublicKey = ExportPublicKey(ephemeral);
			byte[] x25519Secret = DeriveSharedSecret(ephemeral, publicKey);
			(byte[] mlKemCiphertext, byte[] mlKemSecret) = MLKemTestUtils.Encapsulate(mlKem, message);

			using (Assert.Multiple())
			{
				await Assert.That(ciphertext).IsEquivalentTo(Concat(mlKemCiphertext, ephemeralPublicKey), CollectionOrdering.Matching);
				await Assert.That(sharedSecret).IsEquivalentTo(Concat(mlKemSecret, x25519Secret), CollectionOrdering.Matching);
				await Assert.That(x25519Secret).IsEquivalentTo(X25519Function(ephemeralPrivateKey, publicKey), CollectionOrdering.Matching);
				await Assert.That(DeriveSharedSecret(staticKey, ephemeralPublicKey)).IsEquivalentTo(x25519Secret, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(kem, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task EachDecapsulatesWhatThePartsEncapsulate()
	{
		for (int i = 0; i < Iterations; ++i)
		{
			using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
			using X25519MLKem768 fromDecapsulationKey = X25519MLKem768.ImportDecapsulationKey(ExportDecapsulationKey(kem));
			(byte[] mlKemSeed, byte[] privateKey) = Split(ExportPrivateSeed(kem), MLKem768.PrivateSeedLength);
			using X25519 staticKey = X25519.ImportPrivateKey(privateKey);
			using MLKem768 mlKem = MLKem768.ImportPrivateSeed(mlKemSeed);

			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
			(byte[] mlKemCiphertext, byte[] ephemeralPublicKey) = Split(ciphertext, MLKemCiphertextLength);

			using X25519 ephemeral = X25519.GenerateKey();
			(byte[] partsMLKemCiphertext, byte[] partsMLKemSecret) = Encapsulate(mlKem);
			byte[] partsCiphertext = Concat(partsMLKemCiphertext, ExportPublicKey(ephemeral));
			byte[] partsSharedSecret = Concat(partsMLKemSecret, DeriveSharedSecret(ephemeral, ExportPublicKey(staticKey)));

			using (Assert.Multiple())
			{
				await Assert.That(sharedSecret).IsEquivalentTo(Concat(Decapsulate(mlKem, mlKemCiphertext), DeriveSharedSecret(staticKey, ephemeralPublicKey)), CollectionOrdering.Matching);
				await Assert.That(Decapsulate(kem, partsCiphertext)).IsEquivalentTo(partsSharedSecret, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(fromDecapsulationKey, partsCiphertext)).IsEquivalentTo(partsSharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	// Every 32 bytes are an X25519 private key, so only the ML-KEM part of the private formats can be invalid.
	[Test]
	public async Task AnyX25519PrivateKeyIsValid()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		byte[] mlKemSeed = ExportPrivateSeed(kem).AsSpan(0, MLKem768.PrivateSeedLength).ToArray();
		byte[] mlKemDecapsulationKey = ExportDecapsulationKey(kem).AsSpan(0, MLKem768.DecapsulationKeyLength).ToArray();

		using (Assert.Multiple())
		{
			foreach (byte filler in (byte[])[0x00, 0xFF])
			{
				byte[] privateKey = Enumerable.Repeat(filler, 32).ToArray();
				using X25519 x25519 = X25519.ImportPrivateKey(privateKey);
				byte[] seed = Concat(mlKemSeed, privateKey);
				using X25519MLKem768 fromSeed = X25519MLKem768.ImportPrivateSeed(seed);
				using X25519MLKem768 fromDecapsulationKey = X25519MLKem768.ImportDecapsulationKey(Concat(mlKemDecapsulationKey, privateKey));

				await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(seed, CollectionOrdering.Matching);
				await Assert.That(ExportEncapsulationKey(fromSeed).AsSpan(MLKemEncapsulationKeyLength).ToArray()).IsEquivalentTo(ExportPublicKey(x25519), CollectionOrdering.Matching);
				await Assert.That(ExportEncapsulationKey(fromDecapsulationKey)).IsEquivalentTo(ExportEncapsulationKey(fromSeed), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task InvalidMLKemDecapsulationKeysThrow()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		(byte[] mlKemDecapsulationKey, byte[] privateKey) = Split(ExportDecapsulationKey(kem), MLKem768.DecapsulationKeyLength);
		int secretLength = MLKemEncapsulationKeyLength - 32;
		int hashOffset = secretLength + MLKemEncapsulationKeyLength;
		byte[][] invalid = [Flip(mlKemDecapsulationKey, hashOffset), WithLargeCoefficient(mlKemDecapsulationKey, 0), WithLargeCoefficient(mlKemDecapsulationKey, secretLength)];

		using (Assert.Multiple())
		{
			foreach (byte[] mlKemPart in invalid)
			{
				await Assert.That(() => MLKem768.ImportDecapsulationKey(mlKemPart)).Throws<ArgumentException>();
				await Assert.That(() => X25519MLKem768.ImportDecapsulationKey(Concat(mlKemPart, privateKey))).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	// A small-order X25519 key fails in every encoding, and so does an ML-KEM key that fails the modulus check of FIPS 203 §7.2.
	[Test]
	public async Task InvalidEncapsulationKeysThrow()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		(byte[] mlKemEncapsulationKey, byte[] publicKey) = Split(ExportEncapsulationKey(kem), MLKemEncapsulationKeyLength);
		byte[] invalidMLKemPart = WithLargeCoefficient(mlKemEncapsulationKey, 0);

		using (Assert.Multiple())
		{
			foreach (byte[] invalidPublicKey in SmallOrderPublicKeys())
			{
				await Assert.That(() => X25519MLKem768.ImportEncapsulationKey(Concat(mlKemEncapsulationKey, invalidPublicKey))).Throws<ArgumentException>().WithParameterName("source");
			}

			await Assert.That(() => MLKem768.ImportEncapsulationKey(invalidMLKemPart)).Throws<ArgumentException>();
			await Assert.That(() => X25519MLKem768.ImportEncapsulationKey(Concat(invalidMLKemPart, publicKey))).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	// RFC 7748 accepts every encoding of a u-coordinate; the encapsulation key keeps the one it was given.
	[Test]
	public async Task NonCanonicalX25519KeysAreKeptAndUsed()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		byte[] encapsulationKey = ExportEncapsulationKey(kem);
		encapsulationKey[^1] |= 0x80;
		using X25519MLKem768 encapsulator = X25519MLKem768.ImportEncapsulationKey(encapsulationKey);
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(encapsulator);

		using (Assert.Multiple())
		{
			await Assert.That(ExportEncapsulationKey(encapsulator)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(kem, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	// TLS requires the all-zero check of the X25519 secret; the ciphertext alone decides it, so an unrelated key gives false too.
	[Test]
	public async Task SmallOrderEphemeralKeysReturnFalse()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		using X25519MLKem768 unrelated = X25519MLKem768.GenerateKey();
		byte[] mlKemCiphertext = Encapsulate(kem).Ciphertext.AsSpan(0, MLKemCiphertextLength).ToArray();

		using (Assert.Multiple())
		{
			foreach (byte[] ephemeralPublicKey in SmallOrderPublicKeys())
			{
				foreach (X25519MLKem768 holder in (X25519MLKem768[])[kem, unrelated])
				{
					(bool result, byte[] output) = TryDecapsulate(holder, Concat(mlKemCiphertext, ephemeralPublicKey));
					await Assert.That(result).IsFalse();
					await Assert.That(output).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	public async Task TamperingTheMLKemCiphertextKeepsTheX25519Part()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		using MLKem768 mlKem = MLKem768.ImportPrivateSeed(ExportPrivateSeed(kem).AsSpan(0, MLKem768.PrivateSeedLength));
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
		(byte[] mlKemSecret, byte[] x25519Secret) = Split(sharedSecret, MLKem768.SharedSecretLength);

		foreach (int index in (int[])[0, 1, MLKemCiphertextLength / 2, MLKemCiphertextLength - 1])
		{
			byte[] tampered = Flip(ciphertext, index);
			(byte[] tamperedMLKemSecret, byte[] tamperedX25519Secret) = Split(Decapsulate(kem, tampered), MLKem768.SharedSecretLength);

			using (Assert.Multiple())
			{
				await Assert.That(tamperedX25519Secret).IsEquivalentTo(x25519Secret, CollectionOrdering.Matching).Because($"byte {index}");
				await Assert.That(tamperedMLKemSecret).IsNotEquivalentTo(mlKemSecret).Because($"byte {index}");
				await Assert.That(tamperedMLKemSecret).IsEquivalentTo(Decapsulate(mlKem, tampered.AsSpan(0, MLKemCiphertextLength)), CollectionOrdering.Matching).Because($"byte {index}");
			}
		}
	}

	[Test]
	public async Task SettingBit255OfTheEphemeralKeyKeepsTheSharedSecret()
	{
		for (int i = 0; i < Iterations; ++i)
		{
			using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
			byte[] altered = (byte[])ciphertext.Clone();
			altered[^1] |= 0x80;

			using (Assert.Multiple())
			{
				await Assert.That(altered).IsNotEquivalentTo(ciphertext);
				await Assert.That(Decapsulate(kem, altered)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task DecapsulationMayOverlapEitherPartOfItsInput()
	{
		int ciphertextLength = X25519MLKem768.CiphertextLength;
		int secretLength = X25519MLKem768.SharedSecretLength;
		int boundary = MLKemCiphertextLength;
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
		List<int> mismatches = [];

		foreach (int offset in (int[])[1 - secretLength, -1, 0, boundary - secretLength, boundary - secretLength + 1, boundary - 1, boundary, ciphertextLength - secretLength, ciphertextLength - 1])
		{
			byte[] buffer = new byte[2 * secretLength + ciphertextLength];
			ciphertext.CopyTo(buffer, secretLength);
			bool result = kem.TryDecapsulate(buffer.AsSpan(secretLength, ciphertextLength), buffer.AsSpan(secretLength + offset, secretLength));

			if (!result || !buffer.AsSpan(secretLength + offset, secretLength).SequenceEqual(sharedSecret))
			{
				mismatches.Add(offset);
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	[Test]
	public async Task EveryOverlapOfTheOutputsThrows()
	{
		int ciphertextLength = X25519MLKem768.CiphertextLength;
		int secretLength = X25519MLKem768.SharedSecretLength;
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		byte[] buffer = CreateGuardedBuffer(0, 2 * secretLength + ciphertextLength);
		List<int> failures = [];

		for (int offset = 1 - secretLength; offset < ciphertextLength; ++offset)
		{
			try
			{
				kem.Encapsulate(buffer.AsSpan(secretLength, ciphertextLength), buffer.AsSpan(secretLength + offset, secretLength));
			}
			catch (ArgumentException e) when (e.ParamName is "sharedSecret")
			{
				continue;
			}

			failures.Add(offset);
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(buffer).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task KeyOperationsDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan, such as a field constant or the zetas, allocates a field handle.
		SkipUnlessOptimized<X25519MLKem768>();

		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
		byte[] seed = new byte[X25519MLKem768.PrivateSeedLength];
		byte[] decapsulationKey = new byte[X25519MLKem768.DecapsulationKeyLength];
		byte[] encapsulationKey = new byte[X25519MLKem768.EncapsulationKeyLength];
		byte[] ciphertext = new byte[X25519MLKem768.CiphertextLength];
		byte[] invalidCiphertext = KemCiphertextChecks.Of<X25519MLKem768>().InvalidCiphertexts[0];
		byte[] sharedSecret = new byte[X25519MLKem768.SharedSecretLength];
		byte[] decapsulated = new byte[X25519MLKem768.SharedSecretLength];

		bool results = Exercise(kem, seed, decapsulationKey, encapsulationKey, ciphertext, invalidCiphertext, sharedSecret, decapsulated);
		long before = GC.GetAllocatedBytesForCurrentThread();
		results &= Exercise(kem, seed, decapsulationKey, encapsulationKey, ciphertext, invalidCiphertext, sharedSecret, decapsulated);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(results).IsTrue();
			await Assert.That(decapsulated).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task DisposeErasesTheKey()
	{
		X25519MLKem768 generated = X25519MLKem768.GenerateKey();
		X25519MLKem768 fromDecapsulationKey = X25519MLKem768.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		X25519MLKem768 fromEncapsulationKey = X25519MLKem768.ImportEncapsulationKey(ExportEncapsulationKey(generated));

		foreach (X25519MLKem768 kem in (X25519MLKem768[])[generated, fromDecapsulationKey, fromEncapsulationKey])
		{
			Dictionary<string, byte[]> before = KeyContents(kem);
			kem.Dispose();
			Dictionary<string, byte[]> after = KeyContents(kem);

			using (Assert.Multiple())
			{
				await Assert.That(before.Keys).IsEquivalentTo(["_mlKemKey", "_x25519Key"]);
				await Assert.That(before.Values).All(static bytes => bytes.AsSpan().ContainsAnyExcept((byte)0));
				await Assert.That(after.Values).All(static bytes => !bytes.AsSpan().ContainsAnyExcept((byte)0));
			}
		}
	}

	private static bool Exercise(X25519MLKem768 kem, byte[] seed, byte[] decapsulationKey, byte[] encapsulationKey, byte[] ciphertext, byte[] invalidCiphertext, byte[] sharedSecret, byte[] decapsulated)
	{
		bool results = true;

		for (int i = 0; i < 4; ++i)
		{
			kem.ExportPrivateSeed(seed);
			kem.ExportDecapsulationKey(decapsulationKey);
			kem.ExportEncapsulationKey(encapsulationKey);
			kem.Encapsulate(ciphertext, sharedSecret);
			results &= !kem.TryDecapsulate(invalidCiphertext, decapsulated);
			results &= kem.TryDecapsulate(ciphertext, decapsulated);
		}

		return results;
	}

	private static byte[] WithLargeCoefficient(byte[] source, int offset)
	{
		byte[] result = (byte[])source.Clone();
		result[offset] = 0xFF;
		result[offset + 1] |= 0x0F;
		return result;
	}

	private static Dictionary<string, byte[]> KeyContents(X25519MLKem768 kem)
	{
		object key = typeof(X25519MLKem768).GetField("_key", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(kem) ?? throw new InvalidOperationException("X25519MLKem768 has no key field.");
		return key.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).ToDictionary(static field => field.Name, field => Contents(field.GetValue(key)));
	}

	// The polynomials of ML-KEM are an array; everything else is a struct without references.
	private static byte[] Contents(object? value)
	{
		switch (value)
		{
			case null:
			{
				return [];
			}
			case short[] array:
			{
				return MemoryMarshal.AsBytes(array.AsSpan()).ToArray();
			}
			default:
			{
				Type type = value.GetType();

				if (!type.IsValueType)
				{
					throw new InvalidOperationException($"The test does not know how to check {type.Name}.");
				}

				MethodInfo bytes = typeof(X25519MLKemTest).GetMethod(nameof(Bytes), BindingFlags.Static | BindingFlags.NonPublic) ?? throw new MissingMethodException(nameof(X25519MLKemTest), nameof(Bytes));
				return bytes.MakeGenericMethod(type).Invoke(null, [value]) as byte[] ?? [.. type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).SelectMany(field => Contents(field.GetValue(value)))];
			}
		}
	}

	private static byte[]? Bytes<TValue>(object value) where TValue : struct
	{
		if (RuntimeHelpers.IsReferenceOrContainsReferences<TValue>())
		{
			return null;
		}

		TValue copy = (TValue)value;
		return MemoryMarshal.AsBytes(new ReadOnlySpan<TValue>(in copy)).ToArray();
	}
}
