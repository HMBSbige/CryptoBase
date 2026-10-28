using CryptoBase.Abstractions.Kems;
using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;
using CryptoBase.Tests.Kems.MLKem;
using CryptoBase.Tests.KeyAgreements;
using System.Numerics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static CryptoBase.Tests.Kems.Hybrid.EcMLKemTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems.Hybrid;

[GenerateGenericTest(typeof(SecP256r1MLKem768), typeof(EcdhP256), typeof(MLKem768))]
[GenerateGenericTest(typeof(SecP384r1MLKem1024), typeof(EcdhP384), typeof(MLKem1024))]
public class EcMLKemTest<T, TEcdh, TMLKem> where T : class, IKem<T> where TEcdh : class, IKeyAgreement<TEcdh> where TMLKem : class, IKem<TMLKem>
{
	private const int Iterations = 4;

	[Test]
	public async Task KeysConcatenateTheirParts()
	{
		using T kem = T.GenerateKey();
		(byte[] privateKey, byte[] mlKemSeed) = Split(ExportPrivateSeed(kem), TEcdh.PrivateKeyLength);
		using TEcdh ecdh = TEcdh.ImportPrivateKey(privateKey);
		using TMLKem mlKem = TMLKem.ImportPrivateSeed(mlKemSeed);

		using (Assert.Multiple())
		{
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(Concat(ExportPublicKey(ecdh), ExportEncapsulationKey(mlKem)), CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(kem)).IsEquivalentTo(Concat(privateKey, ExportDecapsulationKey(mlKem)), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task EncapsulationConcatenatesItsParts()
	{
		CurveCase curve = CurveOf<TEcdh>();
		using T kem = T.GenerateKey();
		(byte[] publicKey, byte[] mlKemEncapsulationKey) = Split(ExportEncapsulationKey(kem), TEcdh.PublicKeyLength);
		using TEcdh staticKey = TEcdh.ImportPrivateKey(ExportPrivateSeed(kem).AsSpan(0, TEcdh.PrivateKeyLength));
		using TMLKem mlKem = TMLKem.ImportEncapsulationKey(mlKemEncapsulationKey);
		using TEcdh randomKey = TEcdh.GenerateKey();
		byte[][] ephemeralPrivateKeys = [curve.EncodeScalar(BigInteger.One), curve.EncodeScalar(curve.Order - 1), ExportPrivateKey(randomKey)];

		foreach (byte[] ephemeralPrivateKey in ephemeralPrivateKeys)
		{
			byte[] message = RandomNumberGenerator.GetBytes(32);
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem, ephemeralPrivateKey, message);
			using TEcdh ephemeral = TEcdh.ImportPrivateKey(ephemeralPrivateKey);
			byte[] ephemeralPublicKey = ExportPublicKey(ephemeral);
			byte[] ecdhSecret = DeriveSharedSecret(ephemeral, publicKey);
			(byte[] mlKemCiphertext, byte[] mlKemSecret) = MLKemTestUtils.Encapsulate(mlKem, message);

			using (Assert.Multiple())
			{
				await Assert.That(ciphertext).IsEquivalentTo(Concat(ephemeralPublicKey, mlKemCiphertext), CollectionOrdering.Matching);
				await Assert.That(sharedSecret).IsEquivalentTo(Concat(ecdhSecret, mlKemSecret), CollectionOrdering.Matching);
				await Assert.That(DeriveSharedSecret(staticKey, ephemeralPublicKey)).IsEquivalentTo(ecdhSecret, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(kem, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task EachDecapsulatesWhatThePartsEncapsulate()
	{
		for (int i = 0; i < Iterations; ++i)
		{
			using T kem = T.GenerateKey();
			using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(kem));
			(byte[] privateKey, byte[] mlKemSeed) = Split(ExportPrivateSeed(kem), TEcdh.PrivateKeyLength);
			using TEcdh staticKey = TEcdh.ImportPrivateKey(privateKey);
			using TMLKem mlKem = TMLKem.ImportPrivateSeed(mlKemSeed);

			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
			(byte[] ephemeralPublicKey, byte[] mlKemCiphertext) = Split(ciphertext, TEcdh.PublicKeyLength);

			using TEcdh ephemeral = TEcdh.GenerateKey();
			(byte[] partsMLKemCiphertext, byte[] partsMLKemSecret) = Encapsulate(mlKem);
			byte[] partsCiphertext = Concat(ExportPublicKey(ephemeral), partsMLKemCiphertext);
			byte[] partsSharedSecret = Concat(DeriveSharedSecret(ephemeral, ExportPublicKey(staticKey)), partsMLKemSecret);

			using (Assert.Multiple())
			{
				await Assert.That(sharedSecret).IsEquivalentTo(Concat(DeriveSharedSecret(staticKey, ephemeralPublicKey), Decapsulate(mlKem, mlKemCiphertext)), CollectionOrdering.Matching);
				await Assert.That(Decapsulate(kem, partsCiphertext)).IsEquivalentTo(partsSharedSecret, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(fromDecapsulationKey, partsCiphertext)).IsEquivalentTo(partsSharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task PrivateKeysOutsideTheRangeThrow()
	{
		CurveCase curve = CurveOf<TEcdh>();
		using T kem = T.GenerateKey();
		byte[] mlKemSeed = ExportPrivateSeed(kem).AsSpan(TEcdh.PrivateKeyLength).ToArray();
		byte[] mlKemDecapsulationKey = ExportDecapsulationKey(kem).AsSpan(TEcdh.PrivateKeyLength).ToArray();
		byte[][] invalid = [curve.EncodeScalar(BigInteger.Zero), curve.EncodeScalar(curve.Order), Enumerable.Repeat((byte)0xFF, TEcdh.PrivateKeyLength).ToArray()];
		CurvePoint g = curve.Reference.Generator;

		using (Assert.Multiple())
		{
			foreach (byte[] privateKey in invalid)
			{
				await Assert.That(() => T.ImportPrivateSeed(Concat(privateKey, mlKemSeed))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportDecapsulationKey(Concat(privateKey, mlKemDecapsulationKey))).Throws<ArgumentException>().WithParameterName("source");
			}

			foreach ((BigInteger d, CurvePoint q) in ((BigInteger, CurvePoint)[])[(BigInteger.One, g), (curve.Order - 1, g with { Y = curve.Reference.P - g.Y })])
			{
				byte[] privateKey = curve.EncodeScalar(d);
				using T fromSeed = T.ImportPrivateSeed(Concat(privateKey, mlKemSeed));
				using T fromDecapsulationKey = T.ImportDecapsulationKey(Concat(privateKey, mlKemDecapsulationKey));

				await Assert.That(ExportEncapsulationKey(fromSeed).AsSpan(0, TEcdh.PublicKeyLength).ToArray()).IsEquivalentTo(curve.EncodePoint(q), CollectionOrdering.Matching);
				await Assert.That(ExportEncapsulationKey(fromDecapsulationKey)).IsEquivalentTo(ExportEncapsulationKey(fromSeed), CollectionOrdering.Matching);
			}

			foreach (byte filler in (byte[])[0x00, 0xFF])
			{
				byte[] seed = Concat(curve.EncodeScalar(BigInteger.One), Enumerable.Repeat(filler, TMLKem.PrivateSeedLength).ToArray());
				using T fromSeed = T.ImportPrivateSeed(seed);

				await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task InvalidMLKemDecapsulationKeysThrow()
	{
		using T kem = T.GenerateKey();
		(byte[] privateKey, byte[] mlKemDecapsulationKey) = Split(ExportDecapsulationKey(kem), TEcdh.PrivateKeyLength);
		int secretLength = TMLKem.EncapsulationKeyLength - 32;
		int hashOffset = secretLength + TMLKem.EncapsulationKeyLength;
		byte[][] invalid = [Flip(mlKemDecapsulationKey, hashOffset), WithLargeCoefficient(mlKemDecapsulationKey, 0), WithLargeCoefficient(mlKemDecapsulationKey, secretLength)];

		using (Assert.Multiple())
		{
			foreach (byte[] mlKemPart in invalid)
			{
				await Assert.That(() => TMLKem.ImportDecapsulationKey(mlKemPart)).Throws<ArgumentException>();
				await Assert.That(() => T.ImportDecapsulationKey(Concat(privateKey, mlKemPart))).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	[Test]
	public async Task InvalidEncapsulationKeysThrow()
	{
		using T kem = T.GenerateKey();
		(byte[] publicKey, byte[] mlKemEncapsulationKey) = Split(ExportEncapsulationKey(kem), TEcdh.PublicKeyLength);
		byte[] invalidMLKemPart = WithLargeCoefficient(mlKemEncapsulationKey, 0);

		using (Assert.Multiple())
		{
			foreach (byte[] invalidPublicKey in KeyAgreementChecks.Of<TEcdh>().InvalidPublicKeys)
			{
				await Assert.That(() => T.ImportEncapsulationKey(Concat(invalidPublicKey, mlKemEncapsulationKey))).Throws<ArgumentException>().WithParameterName("source");
			}

			await Assert.That(() => TMLKem.ImportEncapsulationKey(invalidMLKemPart)).Throws<ArgumentException>();
			await Assert.That(() => T.ImportEncapsulationKey(Concat(publicKey, invalidMLKemPart))).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	[Test]
	public async Task TamperingTheMLKemCiphertextKeepsTheEcdhPart()
	{
		using T kem = T.GenerateKey();
		using TMLKem mlKem = TMLKem.ImportPrivateSeed(ExportPrivateSeed(kem).AsSpan(TEcdh.PrivateKeyLength));
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
		(byte[] ecdhSecret, byte[] mlKemSecret) = Split(sharedSecret, TEcdh.SharedSecretLength);

		foreach (int index in (int[])[TEcdh.PublicKeyLength, TEcdh.PublicKeyLength + 1, (TEcdh.PublicKeyLength + T.CiphertextLength) / 2, T.CiphertextLength - 1])
		{
			byte[] tampered = Flip(ciphertext, index);
			(byte[] tamperedEcdhSecret, byte[] tamperedMLKemSecret) = Split(Decapsulate(kem, tampered), TEcdh.SharedSecretLength);

			using (Assert.Multiple())
			{
				await Assert.That(tamperedEcdhSecret).IsEquivalentTo(ecdhSecret, CollectionOrdering.Matching).Because($"byte {index}");
				await Assert.That(tamperedMLKemSecret).IsNotEquivalentTo(mlKemSecret).Because($"byte {index}");
				await Assert.That(tamperedMLKemSecret).IsEquivalentTo(Decapsulate(mlKem, tampered.AsSpan(TEcdh.PublicKeyLength)), CollectionOrdering.Matching).Because($"byte {index}");
			}
		}
	}

	[Test]
	public async Task NegatingTheEphemeralPublicKeyKeepsTheSharedSecret()
	{
		CurveCase curve = CurveOf<TEcdh>();

		for (int i = 0; i < Iterations; ++i)
		{
			using T kem = T.GenerateKey();
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
			(byte[] ephemeralPublicKey, byte[] mlKemCiphertext) = Split(ciphertext, TEcdh.PublicKeyLength);
			BigInteger y = curve.DecodePoint(ephemeralPublicKey).Y;
			byte[] negated = [.. ephemeralPublicKey.AsSpan(0, 1 + curve.FieldLength), .. curve.EncodeCoordinate(curve.Reference.P - y)];
			byte[] altered = Concat(negated, mlKemCiphertext);

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
		int ciphertextLength = T.CiphertextLength;
		int secretLength = T.SharedSecretLength;
		int boundary = TEcdh.PublicKeyLength;
		using T kem = T.GenerateKey();
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
		int ciphertextLength = T.CiphertextLength;
		int secretLength = T.SharedSecretLength;
		using T kem = T.GenerateKey();
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
	// Background GC can overcount unused allocation-context space, causing intermittent allocation assertion failures.
	// https://github.com/dotnet/runtime/pull/134855
	public async Task KeyOperationsDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan, such as the field modulus or the zetas, allocates a field handle.
		SkipUnlessOptimized<T>();

		using T kem = T.GenerateKey();
		byte[] seed = new byte[T.PrivateSeedLength];
		byte[] decapsulationKey = new byte[T.DecapsulationKeyLength];
		byte[] encapsulationKey = new byte[T.EncapsulationKeyLength];
		byte[] ciphertext = new byte[T.CiphertextLength];
		byte[] invalidCiphertext = KemCiphertextChecks.Of<T>().InvalidCiphertexts[0];
		byte[] sharedSecret = new byte[T.SharedSecretLength];
		byte[] decapsulated = new byte[T.SharedSecretLength];

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
		T generated = T.GenerateKey();
		T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		T fromEncapsulationKey = T.ImportEncapsulationKey(ExportEncapsulationKey(generated));

		foreach (T kem in (T[])[generated, fromDecapsulationKey, fromEncapsulationKey])
		{
			Dictionary<string, byte[]> before = KeyContents(kem);
			kem.Dispose();
			Dictionary<string, byte[]> after = KeyContents(kem);

			using (Assert.Multiple())
			{
				await Assert.That(before.Keys).IsEquivalentTo(["_ecKey", "_mlKemKey"]);
				await Assert.That(before.Values).All(static bytes => bytes.AsSpan().ContainsAnyExcept((byte)0));
				await Assert.That(after.Values).All(static bytes => !bytes.AsSpan().ContainsAnyExcept((byte)0));
			}
		}
	}

	private static bool Exercise(T kem, byte[] seed, byte[] decapsulationKey, byte[] encapsulationKey, byte[] ciphertext, byte[] invalidCiphertext, byte[] sharedSecret, byte[] decapsulated)
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

	private static Dictionary<string, byte[]> KeyContents(object kem)
	{
		object key = kem.GetType().GetField("_key", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(kem) ?? throw new InvalidOperationException($"{kem.GetType().Name} has no key field.");
		return key.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).ToDictionary(static field => field.Name, field => Contents(field.GetValue(key)));
	}

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

				MethodInfo bytes = typeof(EcMLKemTest<T, TEcdh, TMLKem>).GetMethod(nameof(Bytes), BindingFlags.Static | BindingFlags.NonPublic) ?? throw new MissingMethodException(nameof(EcMLKemTest), nameof(Bytes));
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

public class EcMLKemTest
{
	[Test]
	public async Task LengthsAreFixed()
	{
		using (Assert.Multiple())
		{
			await Assert.That((SecP256r1MLKem768.EncapsulationKeyLength, SecP256r1MLKem768.CiphertextLength, SecP256r1MLKem768.SharedSecretLength, SecP256r1MLKem768.PrivateSeedLength, SecP256r1MLKem768.DecapsulationKeyLength)).IsEqualTo((1249, 1153, 64, 96, 2432));
			await Assert.That((SecP384r1MLKem1024.EncapsulationKeyLength, SecP384r1MLKem1024.CiphertextLength, SecP384r1MLKem1024.SharedSecretLength, SecP384r1MLKem1024.PrivateSeedLength, SecP384r1MLKem1024.DecapsulationKeyLength)).IsEqualTo((1665, 1665, 80, 112, 3216));
		}
	}
}
