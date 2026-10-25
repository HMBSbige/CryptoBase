using CryptoBase.Abstractions.Signatures;
using CryptoBase.EllipticCurves;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.EllipticCurves;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.Signatures.Ecdsa.EcdsaKnownAnswerTest;
using static CryptoBase.Tests.Signatures.Ecdsa.EcdsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Ecdsa;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
internal class EcdsaTest
{
	private const string EcPublicKeyOid = "1.2.840.10045.2.1";

	private static readonly EcdsaSignatureFormat[] Formats = [EcdsaSignatureFormat.Der, EcdsaSignatureFormat.Concatenated];

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task LengthsFollowTheCurve<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		using T key = T.GenerateKey();
		int integerLength = 2 + curve.ScalarBitLength / 8 + 1;
		int maxDerLength = 2 * integerLength + (2 * integerLength < 0x80 ? 2 : 3);

		using (Assert.Multiple())
		{
			await Assert.That(T.PrivateKeyLength).IsEqualTo(curve.ScalarLength);
			await Assert.That(T.PublicKeyLength).IsEqualTo(curve.PublicKeyLength);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				await Assert.That(key.GetMaxSignatureLength(algorithm)).IsEqualTo(maxDerLength);
			}
		}
	}

	[Test]
	public async Task LengthsAreFixed()
	{
		using EcdsaP256 p256 = EcdsaP256.GenerateKey();
		using EcdsaP384 p384 = EcdsaP384.GenerateKey();
		using EcdsaP521 p521 = EcdsaP521.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That(Lengths(p256)).IsEqualTo((32, 65, 91, 150, 72));
			await Assert.That(Lengths(p384)).IsEqualTo((48, 97, 120, 194, 104));
			await Assert.That(Lengths(p521)).IsEqualTo((66, 133, 158, 250, 139));
		}

		static (int, int, int, int, int) Lengths<T>(T key) where T : class, IEcdsa<T>
		{
			return (T.PrivateKeyLength, T.PublicKeyLength, key.SubjectPublicKeyInfoLength, key.Pkcs8PrivateKeyLength, key.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha512));
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task RawKeysRoundTrip<T>() where T : class, IEcdsa<T>
	{
		using T generated = T.GenerateKey();
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);
		using T fromPrivateKey = T.ImportPrivateKey(privateKey);
		using T fromPublicKey = T.ImportPublicKey(publicKey);
		CurveCase curve = CurveOf<T>();
		BigInteger d = new(privateKey, isUnsigned: true, isBigEndian: true);
		byte[] message = CreateDeterministicSource(50);
		byte[] signature = Sign(fromPrivateKey, SignatureAlgorithm.EcdsaSha256, message);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(fromPrivateKey)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(fromPrivateKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(fromPublicKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(publicKey).IsEquivalentTo(curve.EncodePoint(curve.Reference.PublicKey(d)), CollectionOrdering.Matching);
			await Assert.That(fromPublicKey.HasPrivateKey).IsFalse();
			await Assert.That(() => fromPublicKey.ExportPrivateKey(new byte[T.PrivateKeyLength])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(fromPublicKey.Verify(SignatureAlgorithm.EcdsaSha256, message, signature)).IsTrue();
			await Assert.That(generated.Verify(SignatureAlgorithm.EcdsaSha256, message, signature)).IsTrue();
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task PrivateKeysOutsideTheRangeThrow<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		BigInteger n = curve.Order;
		int length = T.PrivateKeyLength;
		byte[] valid = curve.EncodeScalar(n - 1);
		List<byte[]> invalid =
		[
			curve.EncodeScalar(0), curve.EncodeScalar(n), curve.EncodeScalar(n + 1), Enumerable.Repeat((byte)0xFF, length).ToArray(),
			valid.AsSpan(1).ToArray(), [0, .. valid], [], [0, .. curve.EncodeScalar(1)]
		];

		// The leading bytes above that of n, with 1 below them; there are none where n starts with 0xFF.
		for (int top = (int)(n >> 8 * (length - 1)) + 1; top <= 0xFF; ++top)
		{
			invalid.Add(curve.EncodeScalar(((BigInteger)top << 8 * (length - 1)) + 1));
		}

		using T one = T.ImportPrivateKey(curve.EncodeScalar(1));
		using T last = T.ImportPrivateKey(valid);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(one)).IsEquivalentTo(curve.EncodePoint(curve.Reference.Generator), CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(last)).IsEquivalentTo(curve.EncodePoint(curve.Reference.PublicKey(n - 1)), CollectionOrdering.Matching);

			foreach (byte[] encoding in invalid)
			{
				await Assert.That(() => T.ImportPrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task InvalidPublicKeysThrow<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		using T key = T.GenerateKey();
		byte[] publicKey = ExportPublicKey(key);
		int length = curve.FieldLength;
		byte[] x = publicKey.AsSpan(1, length).ToArray();
		byte[] y = publicKey.AsSpan(1 + length).ToArray();
		BigInteger p = curve.FieldModulus;
		BigInteger yValue = new(y, isUnsigned: true, isBigEndian: true);
		byte[][] invalid =
		[
			[(byte)(2 + (y[^1] & 1)), .. x], [0x06, .. x, .. y], [0x07, .. x, .. y], [0x05, .. x, .. y], [0x00], new byte[T.PublicKeyLength],
			[0x04, .. x, .. curve.EncodeCoordinate((yValue + 1) % p)], [0x04, .. curve.EncodeCoordinate(p), .. y], [0x04, .. x, .. curve.EncodeCoordinate(p)],
			publicKey.AsSpan(0, publicKey.Length - 1).ToArray(), [.. publicKey, 0], []
		];

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in invalid)
			{
				await Assert.That(() => T.ImportPublicKey(encoding)).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task OnlyTheAdditionalDataVariesTheSignature<T>() where T : class, IEcdsa<T>
	{
		using T key = T.GenerateKey();
		byte[] message = CreateDeterministicSource(30);
		byte[] additionalData = CreateDeterministicSource(32);

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				foreach (EcdsaSignatureFormat format in Formats)
				{
					byte[] deterministic = Sign(key, algorithm, message, [], format);
					byte[] hedged = Sign(key, algorithm, message, additionalData, format);

					await Assert.That(Sign(key, algorithm, message, [], format)).IsEquivalentTo(deterministic, CollectionOrdering.Matching);
					await Assert.That(Sign(key, algorithm, message, additionalData, format)).IsEquivalentTo(hedged, CollectionOrdering.Matching);
					await Assert.That(hedged).IsNotEquivalentTo(deterministic);
					await Assert.That(Sign(key, algorithm, message, Flip(additionalData, 31), format)).IsNotEquivalentTo(hedged);
					await Assert.That(key.Verify(algorithm, message, deterministic, format)).IsTrue();
					await Assert.That(key.Verify(algorithm, message, hedged, format)).IsTrue();
				}

				byte[] randomized = Sign(key, algorithm, message);
				await Assert.That(randomized).IsNotEquivalentTo(Sign(key, algorithm, message, [], EcdsaSignatureFormat.Der));
				await Assert.That(key.Verify(algorithm, message, randomized, EcdsaSignatureFormat.Der)).IsTrue();
			}
		}
	}

	// The key and hashes are fixed so that they give INTEGERs both with a leading 0 and with a leading byte dropped.
	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task DerSignaturesAreShortest<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		using T key = T.ImportPrivateKey(curve.EncodeScalar(new BigInteger(CreateDeterministicSource(T.PrivateKeyLength), isUnsigned: true) % curve.Order));
		int length = T.PrivateKeyLength;
		int maxLength = key.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha256);
		int longest = 0;
		int shortestInteger = int.MaxValue;
		int mismatches = 0;

		for (int i = 0; i < 1024; ++i)
		{
			byte[] hash = CreateDeterministicSource(32 + i % 33);
			hash[0] ^= (byte)i;
			hash[1] ^= (byte)(i >> 8);
			byte[] der = SignHash(key, SignatureAlgorithm.EcdsaSha256, hash, [], EcdsaSignatureFormat.Der);
			byte[] concatenated = SignHash(key, SignatureAlgorithm.EcdsaSha256, hash, [], EcdsaSignatureFormat.Concatenated);
			AsnDecoder.ReadSequence(der, AsnEncodingRules.DER, out int offset, out int contentLength, out int consumed);
			ReadOnlySpan<byte> contents = der.AsSpan(offset, contentLength);
			ReadOnlySpan<byte> r = AsnDecoder.ReadIntegerBytes(contents, AsnEncodingRules.DER, out int rLength);
			ReadOnlySpan<byte> s = AsnDecoder.ReadIntegerBytes(contents.Slice(rLength), AsnEncodingRules.DER, out int sLength);
			longest = Math.Max(longest, der.Length);
			shortestInteger = Math.Min(shortestInteger, Math.Min(r.Length, s.Length));

			if (consumed != der.Length || rLength + sLength != contents.Length || !Matches(r, concatenated.AsSpan(0, length)) || !Matches(s, concatenated.AsSpan(length)))
			{
				++mismatches;
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(mismatches).IsZero();
			await Assert.That(longest).IsEqualTo(maxLength);
			await Assert.That(shortestInteger).IsLessThan(length);
		}

		static bool Matches(ReadOnlySpan<byte> integer, ReadOnlySpan<byte> fixedLength)
		{
			return new BigInteger(integer, isBigEndian: true) == new BigInteger(fixedLength, isUnsigned: true, isBigEndian: true);
		}
	}

	// The message gives an r and s that need no leading 0, so that adding one is the only fault.
	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task OnlyStrictDerVerifies<T>() where T : class, IEcdsa<T>
	{
		BigInteger n = CurveOf<T>().Order;
		using T key = T.GenerateKey();
		int length = T.PrivateKeyLength;
		byte[] message;
		byte[] concatenated;
		BigInteger r;
		BigInteger s;
		int attempt = 0;

		do
		{
			message = CreateDeterministicSource(20 + attempt++);
			concatenated = Sign(key, SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Concatenated);
			r = new BigInteger(concatenated.AsSpan(0, length), isUnsigned: true, isBigEndian: true);
			s = new BigInteger(concatenated.AsSpan(length), isUnsigned: true, isBigEndian: true);
		}
		while (Integer(r)[2] is 0 || Integer(s)[2] is 0);

		byte[] rInteger = Integer(r);
		byte[] sInteger = Integer(s);
		byte[] signature = Element(0x30, [.. rInteger, .. sInteger]);
		byte[][] invalid =
		[
			Element(0x30, [.. Element(0x02, [0, .. rInteger.AsSpan(2)]), .. sInteger]), Element(0x30, [.. rInteger, .. Element(0x02, [0, .. sInteger.AsSpan(2)])]),
			LongForm(0x30, [.. rInteger, .. sInteger]), [0x30, 0x80, .. rInteger, .. sInteger, 0, 0], [0x30, 0x82, 0, (byte)(rInteger.Length + sInteger.Length), .. rInteger, .. sInteger],
			Element(0x30, [.. LongForm(0x02, rInteger.AsSpan(2).ToArray()), .. sInteger]), Element(0x30, [.. Element(0x02, [0, 0, .. rInteger.AsSpan(2)]), .. sInteger]),
			Element(0x30, [.. rInteger, .. Element(0x02, [0, 0, .. sInteger.AsSpan(2)])]), Element(0x30, [.. Integer(r + n), .. sInteger]),
			Element(0x30, [.. rInteger, .. Integer(s + n)]), Element(0x30, [.. Integer(r - n), .. sInteger]), Element(0x30, [.. rInteger, .. Integer(n - s - n)]),
			Element(0x30, [.. Integer(0), .. sInteger]), Element(0x30, [.. rInteger, .. Integer(0)]), Element(0x30, [.. Integer(n), .. sInteger]),
			Element(0x30, [.. rInteger, .. Integer(n)]), Element(0x30, [.. rInteger]), Element(0x30, [.. rInteger, .. sInteger, .. Integer(1)]),
			Element(0x30, [.. rInteger, .. sInteger, 0x05, 0x00]), Element(0x30, [.. rInteger, .. Element(0x02, [])]), [.. signature, 0],
			Element(0x31, [.. rInteger, .. sInteger]), Element(0x30, [0x03, .. rInteger.AsSpan(1), .. sInteger]), Element(0x30, [0x02, 0x81, .. rInteger.AsSpan(1), .. sInteger]),
			[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, .. rInteger, .. sInteger], [0x30, 0xFF, .. rInteger, .. sInteger], signature.AsSpan(0, signature.Length - 1).ToArray(),
			[0x30], [.. Header(0x30, rInteger.Length + sInteger.Length + 1), .. rInteger, .. sInteger], [], [0x30, 0x00]
		];
		byte[][] invalidConcatenated =
		[
			concatenated.AsSpan(0, concatenated.Length - 1).ToArray(), [.. concatenated, 0], [0, .. concatenated], [.. new byte[length], .. concatenated.AsSpan(length)],
			[.. concatenated.AsSpan(0, length), .. new byte[length]], [.. CurveCase.EncodeInteger(n, length), .. concatenated.AsSpan(length)],
			[.. concatenated.AsSpan(0, length), .. CurveCase.EncodeInteger(n, length)], [.. Enumerable.Repeat((byte)0xFF, length), .. concatenated.AsSpan(length)]
		];

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, signature)).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, Element(0x30, [.. rInteger, .. Integer(n - s)]))).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, concatenated, EcdsaSignatureFormat.Concatenated)).IsTrue();

			for (int i = 0; i < invalid.Length; ++i)
			{
				await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, invalid[i])).IsFalse().Because($"DER case {i}");
			}

			for (int i = 0; i < invalidConcatenated.Length; ++i)
			{
				await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, invalidConcatenated[i], EcdsaSignatureFormat.Concatenated)).IsFalse().Because($"r ‖ s case {i}");
			}
		}
	}

	[Test]
	public async Task P521SignaturesTakeTheLongLengthForm()
	{
		CurveCase curve = CurveOf<EcdsaP521>();
		using EcdsaP521 key = EcdsaP521.ImportPrivateKey(curve.EncodeScalar(curve.Order / 3));
		byte[] message = CreateDeterministicSource(10);
		byte[] signature = Sign(key, SignatureAlgorithm.EcdsaSha512, message, [], EcdsaSignatureFormat.Der);
		byte[] contents = signature.AsSpan(3).ToArray();

		using (Assert.Multiple())
		{
			await Assert.That(contents.Length).IsBetween(0x80, 0xFF);
			await Assert.That(signature.AsSpan(0, 3).ToArray()).IsEquivalentTo((byte[])[0x30, 0x81, (byte)contents.Length], CollectionOrdering.Matching);
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha512, message, signature)).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha512, message, [0x30, 0x82, 0, (byte)contents.Length, .. contents])).IsFalse();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha512, message, [0x30, 0x83, 0, 0, (byte)contents.Length, .. contents])).IsFalse();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha512, message, [0x30, (byte)contents.Length, .. contents])).IsFalse();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha512, message, [0x30, 0x80, .. contents, 0, 0])).IsFalse();
		}
	}

	// e ≡ 0 makes u1·G the point at infinity.
	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task HashesOfAnyLengthAreTruncated<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		using T key = T.GenerateKey();
		int length = T.PrivateKeyLength;
		int shift = 8 * length - curve.ScalarBitLength;
		byte[] publicKey = ExportPublicKey(key);
		List<byte[]> hashes = [];

		foreach (int hashLength in (int[])[0, 1, 20, length - 1, length, length + 1, 48, 64, 100])
		{
			hashes.Add(CreateDeterministicSource(hashLength));
		}

		// Each of these has e = 0.
		hashes.Add(new byte[length]);
		hashes.Add(CurveCase.EncodeInteger(curve.Order << shift, length));
		hashes.Add([.. CurveCase.EncodeInteger(curve.Order << shift, length), .. CreateDeterministicSource(7)]);
		List<int> failed = [];

		for (int i = 0; i < hashes.Count; ++i)
		{
			byte[] hash = hashes[i];
			BigInteger e = new(TruncatedHash(hash, curve.Order, curve.ScalarBitLength, length), isUnsigned: true, isBigEndian: true);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				byte[] signature = SignHash(key, algorithm, hash, CreateDeterministicSource(3), EcdsaSignatureFormat.Concatenated);

				if (!ReferenceVerifies(curve, publicKey, e, signature) || !key.VerifyHash(hash, signature, EcdsaSignatureFormat.Concatenated))
				{
					failed.Add(i);
				}
			}
		}

		byte[] zeroSignature = SignHash(key, SignatureAlgorithm.EcdsaSha256, new byte[length], [], EcdsaSignatureFormat.Der);

		using (Assert.Multiple())
		{
			await Assert.That(failed).IsEmpty();

			foreach (byte[] hash in hashes.Slice(hashes.Count - 3, 3))
			{
				await Assert.That(key.VerifyHash(hash, zeroSignature, EcdsaSignatureFormat.Der)).IsTrue();
			}

			await Assert.That(key.VerifyHash([1], zeroSignature, EcdsaSignatureFormat.Der)).IsFalse();
		}
	}

	// e ≡ −r·d makes R the point at infinity, which verification must reject before it compares x(R) with r.
	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task PointAtInfinityDoesNotVerify<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		using T key = T.GenerateKey();
		int length = T.PrivateKeyLength;
		int shift = 8 * length - curve.ScalarBitLength;
		BigInteger d = new(ExportPrivateKey(key), isUnsigned: true, isBigEndian: true);
		CurvePoint q = reference.PublicKey(d);

		using (Assert.Multiple())
		{
			foreach ((BigInteger r, BigInteger s) in ((BigInteger, BigInteger)[])[(1, 1), (n - 1, n - 1), (d, n / 3)])
			{
				BigInteger e = (n - r * d % n) % n;
				BigInteger w = BigInteger.ModPow(s, n - 2, n);
				byte[] hash = CurveCase.EncodeInteger(e << shift, length);
				byte[] signature = [.. curve.EncodeScalar(r), .. curve.EncodeScalar(s)];

				await Assert.That(reference.Add(reference.Multiply(reference.Generator, e * w % n), reference.Multiply(q, r * w % n))).IsNull();
				await Assert.That(key.VerifyHash(hash, signature, EcdsaSignatureFormat.Concatenated)).IsFalse().Because($"r = {r}, s = {s}");
			}
		}
	}

	// The first verification with an instance goes without the table of its public key, and the later ones use it, so both must decide alike: here valid signatures, the same signatures over other hashes, r and s at the ends of [1, n − 1], and R = O.
	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task FirstAndLaterVerificationsAgree<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		BigInteger n = curve.Order;
		using T signer = T.GenerateKey();
		byte[] publicKey = ExportPublicKey(signer);
		BigInteger d = new(ExportPrivateKey(signer), isUnsigned: true, isBigEndian: true);
		Random random = new(7);
		List<(BigInteger E, byte[] Signature)> cases = [];

		for (int i = 0; i < 4; ++i)
		{
			BigInteger e = EcReference.RandomBelow(random, n);
			byte[] signature = SignHash(signer, SignatureAlgorithm.EcdsaSha256, HashOf(curve, e), [], EcdsaSignatureFormat.Concatenated);
			cases.Add((e, signature));
			cases.Add(((e + 1) % n, signature));
		}

		foreach (BigInteger r in (BigInteger[])[1, n - 1])
		{
			foreach (BigInteger s in (BigInteger[])[1, n - 1])
			{
				byte[] signature = [.. curve.EncodeScalar(r), .. curve.EncodeScalar(s)];
				cases.Add((0, signature));
				cases.Add((EcReference.RandomBelow(random, n), signature));
				cases.Add(((n - r * d % n) % n, signature));
			}
		}

		using T later = T.ImportPublicKey(publicKey);
		List<bool> expected = [.. cases.Select(c => ReferenceVerifies(curve, publicKey, c.E, c.Signature))];
		List<string> failures = [];

		for (int i = 0; i < 2; ++i)
		{
			_ = later.VerifyHash(HashOf(curve, cases[0].E), cases[0].Signature, EcdsaSignatureFormat.Concatenated);
		}

		for (int i = 0; i < cases.Count; ++i)
		{
			(BigInteger e, byte[] signature) = cases[i];
			using T first = T.ImportPublicKey(publicKey);
			byte[] hash = HashOf(curve, e);

			if (first.VerifyHash(hash, signature, EcdsaSignatureFormat.Concatenated) != expected[i] || later.VerifyHash(hash, signature, EcdsaSignatureFormat.Concatenated) != expected[i])
			{
				failures.Add($"e = {e:X}, r ‖ s = {Convert.ToHexString(signature)}, expected {expected[i]}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(expected).Contains(true).And.Contains(false);
			await Assert.That(failures).IsEmpty();
		}
	}

	// Threads that verify with a new instance at once may each build the table of its public key.
	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task ConcurrentVerificationsWithANewInstanceAgree<T>() where T : class, IEcdsa<T>
	{
		const int threadCount = 8;
		using T signer = T.GenerateKey();
		byte[] publicKey = ExportPublicKey(signer);
		byte[] message = CreateDeterministicSource(30);
		byte[] other = CreateDeterministicSource(31);
		byte[] signature = Sign(signer, SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Der);
		int failures = 0;

		for (int round = 0; round < 4; ++round)
		{
			using T key = T.ImportPublicKey(publicKey);
			using Barrier barrier = new(threadCount);
			Task[] tasks = new Task[threadCount];

			for (int i = 0; i < tasks.Length; ++i)
			{
				tasks[i] = Task.Factory.StartNew(() =>
				{
					barrier.SignalAndWait();

					for (int k = 0; k < 4; ++k)
					{
						if (!key.Verify(SignatureAlgorithm.EcdsaSha256, message, signature) || key.Verify(SignatureAlgorithm.EcdsaSha256, other, signature))
						{
							Interlocked.Increment(ref failures);
						}
					}
				}, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
			}

			await Task.WhenAll(tasks);
		}

		await Assert.That(failures).IsZero();
	}

	// The table belongs to the public key, so whatever replaces the key must drop it: otherwise the new key would verify as the old one.
	[Test]
	public async Task ReplacingTheKeyDropsTheTable()
	{
		CurveCase curve = CurveOf<EcdsaP256>();
		byte[] algorithmIdentifier = AlgorithmIdentifier(curve.Parameters.Oid);
		using EcdsaP256 first = EcdsaP256.GenerateKey();
		using EcdsaP256 second = EcdsaP256.GenerateKey();
		byte[] message = CreateDeterministicSource(20);
		byte[] firstPublicKey = ExportPublicKey(first);
		byte[] firstSignature = Sign(first, SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Der);
		byte[] secondSignature = Sign(second, SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Der);
		byte[] secondPublicKey = ExportPublicKey(second);
		byte[] secondPrivateKey = ExportPrivateKey(second);
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(second);
		byte[] pkcs8 = ExportPkcs8PrivateKey(second);
		List<string> failures = [];

		for (int i = 0; i < 5; ++i)
		{
			EcdsaKey<P256Curve, P256Field, P256Order> core = default;
			core.ImportPublicKey(firstPublicKey);
			bool verified = core.Verify(SignatureAlgorithm.EcdsaSha256, message, firstSignature) & core.Verify(SignatureAlgorithm.EcdsaSha256, message, firstSignature);

			switch (i)
			{
				case 0:
					core.ImportPublicKey(secondPublicKey);
					break;
				case 1:
					core.ImportSubjectPublicKeyInfo(algorithmIdentifier, subjectPublicKeyInfo);
					break;
				case 2:
					core.ImportPrivateKey(secondPrivateKey);
					break;
				case 3:
					core.ImportPkcs8PrivateKey(algorithmIdentifier, pkcs8);
					break;
				default:
					core.GenerateKey();
					break;
			}

			for (int k = 0; k < 3; ++k)
			{
				verified &= !core.Verify(SignatureAlgorithm.EcdsaSha256, message, firstSignature) && (i is 4 || core.Verify(SignatureAlgorithm.EcdsaSha256, message, secondSignature));
			}

			if (!verified)
			{
				failures.Add($"replacement {i}");
			}

			core.Clear();
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task Pkcs8ImportAcceptsOptionalPartsThatMatch<T>() where T : class, IEcdsa<T>
	{
		string curveOid = CurveOf<T>().Parameters.Oid;
		using T key = T.GenerateKey();
		byte[] d = ExportPrivateKey(key);
		byte[] q = ExportPublicKey(key);
		byte[] expected = ExportPkcs8PrivateKey(key);
		byte[][] encodings =
		[
			Pkcs8(curveOid, EcPrivateKey(1, d, null, null)), Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, null)), Pkcs8(curveOid, EcPrivateKey(1, d, null, q)),
			Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, q)), Pkcs8(curveOid, EcPrivateKey(1, d, null, null), q), Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, q), q)
		];

		using (Assert.Multiple())
		{
			await Assert.That(encodings[3]).IsEquivalentTo(expected, CollectionOrdering.Matching);

			foreach (byte[] encoding in encodings)
			{
				using T imported = T.ImportPkcs8PrivateKey(encoding);
				await Assert.That(ExportPkcs8PrivateKey(imported)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task Pkcs8ImportRejectsInconsistentKeys<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		string curveOid = curve.Parameters.Oid;
		string otherCurveOid = CurveCase.All().First(candidate => candidate.Name != curve.Name).Parameters.Oid;
		using T key = T.GenerateKey();
		using T other = T.GenerateKey();
		byte[] d = ExportPrivateKey(key);
		byte[] q = ExportPublicKey(key);
		byte[] otherQ = ExportPublicKey(other);
		byte[] compressedQ = [(byte)(2 + (q[^1] & 1)), .. q.AsSpan(1, curve.FieldLength)];
		byte[] valid = EcPrivateKey(1, d, curveOid, q);
		AsnWriter nullParameters = new(AsnEncodingRules.DER);

		using (nullParameters.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
		{
			nullParameters.WriteNull();
		}

		byte[][] invalid =
		[
			Pkcs8(curveOid, EcPrivateKey(1, d, otherCurveOid, q)), Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, otherQ)), Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, compressedQ)),
			Pkcs8(curveOid, EcPrivateKey(1, d, null, otherQ)), Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, q), otherQ), Pkcs8(curveOid, EcPrivateKey(1, d, null, null), compressedQ),
			Pkcs8(curveOid, EcPrivateKey(0, d, curveOid, q)), Pkcs8(curveOid, EcPrivateKey(2, d, curveOid, q)),
			Pkcs8(curveOid, EcPrivateKey(1, d.AsSpan(1).ToArray(), curveOid, null)), Pkcs8(curveOid, EcPrivateKey(1, [0, .. d], curveOid, null)),
			Pkcs8(curveOid, EcPrivateKey(1, curve.EncodeScalar(0), null, null)), Pkcs8(curveOid, EcPrivateKey(1, curve.EncodeScalar(curve.Order), null, null)),
			Pkcs8(curveOid, EcPrivateKey(1, Enumerable.Repeat((byte)0xFF, d.Length).ToArray(), null, null)),
			Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, q, [0x05, 0x00])), Pkcs8(curveOid, [.. valid, 0x05, 0x00]), Pkcs8(curveOid, [.. valid, 0]),
			Pkcs8(curveOid, EcPrivateKey(1, d, null, null, [.. Element(0xA1, Element(0x03, [0, .. q])), .. Element(0xA0, Oid(curveOid))])),
			Pkcs8(curveOid, EcPrivateKey(1, d, null, null, nullParameters.Encode())), Pkcs8(curveOid, EcPrivateKey(1, d, null, null, Element(0xA2, [0x05, 0x00]))),
			Pkcs8(curveOid, EcPrivateKey(1, d, null, null, Element(0xA1, Element(0x03, [1, .. q])))), Pkcs8(curveOid, EcPrivateKey(1, d, null, null, Element(0xA1, Element(0x04, q)))),
			Pkcs8(curveOid, EcPrivateKey(1, d, null, null, Element(0xA1, [.. Element(0x03, [0, .. q]), 0x05, 0x00]))), Pkcs8(curveOid, EcPrivateKey(1, d, null, null, Element(0xA0, [.. Oid(curveOid), 0x05, 0x00]))),
			Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, q, Element(0xA1, Element(0x03, [0, .. q])))), Pkcs8(curveOid, [0x04, (byte)d.Length, .. d]),
			Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, [])), Pkcs8(curveOid, valid, []), Pkcs8(otherCurveOid, valid)
		];

		using T imported = T.ImportPkcs8PrivateKey(Pkcs8(curveOid, valid));

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(d, CollectionOrdering.Matching);

			for (int i = 0; i < invalid.Length; ++i)
			{
				byte[] encoding = invalid[i];
				await Assert.That(() => T.ImportPkcs8PrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because($"case {i}");
			}
		}
	}

	[Test]
	public async Task FailedPkcs8ImportErasesTheKey()
	{
		CurveCase curve = CurveOf<EcdsaP256>();
		string curveOid = curve.Parameters.Oid;
		byte[] algorithmIdentifier = AlgorithmIdentifier(curveOid);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		using EcdsaP256 other = EcdsaP256.GenerateKey();
		byte[] d = ExportPrivateKey(key);
		byte[] otherQ = ExportPublicKey(other);
		List<bool> erased = [];

		foreach (byte[] encoding in (byte[][])[Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, otherQ)), Pkcs8(curveOid, EcPrivateKey(1, d, curveOid, null), otherQ)])
		{
			EcdsaKey<P256Curve, P256Field, P256Order> core = default;

			try
			{
				core.ImportPkcs8PrivateKey(algorithmIdentifier, encoding);
			}
			catch (ArgumentException)
			{
				erased.Add(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<EcdsaKey<P256Curve, P256Field, P256Order>, byte>(ref core), Unsafe.SizeOf<EcdsaKey<P256Curve, P256Field, P256Order>>()).IndexOfAnyExcept((byte)0) < 0);
			}
		}

		await Assert.That(erased).IsEquivalentTo([true, true], CollectionOrdering.Matching);
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task DisposedInstancesThrow<T>() where T : class, IEcdsa<T>
	{
		T key = T.GenerateKey();
		byte[] message = CreateDeterministicSource(10);
		byte[] signature = Sign(key, SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Concatenated);
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.ExportPrivateKey(new byte[T.PrivateKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPublicKey(new byte[T.PublicKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Sign(SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Der, new byte[100])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.SignHash(SignatureAlgorithm.EcdsaSha256, message, [], EcdsaSignatureFormat.Der, new byte[100])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Verify(SignatureAlgorithm.EcdsaSha256, message, signature, EcdsaSignatureFormat.Concatenated)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.VerifyHash(message, signature, EcdsaSignatureFormat.Concatenated)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task SigningAndVerificationDoNotAllocate<T>() where T : class, IEcdsa<T>
	{
		// Without optimization, every read of a constant ReadOnlySpan<ulong>, such as the curve constants, allocates a field handle.
		if (typeof(T).Assembly.GetCustomAttribute<DebuggableAttribute>()?.IsJITOptimizerDisabled is true)
		{
			Skip.Test("The implementation is not optimized.");
		}

		using T key = T.GenerateKey();
		using T verifier = T.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(100);
		byte[] signature = new byte[key.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha512)];

		// Before the measurement, the second verification with key allocates the table of its public key; within it, key verifies with that table and verifier for the first time, without one.
		bool valid = Exercise(key, message, signature);
		int written = key.Sign(SignatureAlgorithm.EcdsaSha256, message, signature);
		long before = GC.GetAllocatedBytesForCurrentThread();
		valid &= verifier.Verify(SignatureAlgorithm.EcdsaSha256, message, signature.AsSpan(0, written));
		valid &= Exercise(key, message, signature);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(valid).IsTrue();
		}

		static bool Exercise(T key, byte[] message, byte[] signature)
		{
			bool valid = true;

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				int written = key.Sign(algorithm, message, signature);
				valid &= key.Verify(algorithm, message, signature.AsSpan(0, written));
				written = key.Sign(algorithm, message, [], EcdsaSignatureFormat.Concatenated, signature);
				valid &= key.Verify(algorithm, message, signature.AsSpan(0, written), EcdsaSignatureFormat.Concatenated);
			}

			return valid;
		}
	}

	// A hash of the length of n that truncates to e.
	private static byte[] HashOf(CurveCase curve, BigInteger e)
	{
		return CurveCase.EncodeInteger(e << 8 * curve.ScalarLength - curve.ScalarBitLength, curve.ScalarLength);
	}

	private static bool ReferenceVerifies(CurveCase curve, byte[] publicKey, BigInteger e, byte[] concatenated)
	{
		EcReference reference = curve.Reference;
		int length = curve.ScalarLength;
		BigInteger r = new(concatenated.AsSpan(0, length), isUnsigned: true, isBigEndian: true);
		BigInteger s = new(concatenated.AsSpan(length), isUnsigned: true, isBigEndian: true);
		BigInteger n = reference.N;
		BigInteger w = BigInteger.ModPow(s, n - 2, n);
		CurvePoint q = new(new BigInteger(publicKey.AsSpan(1, curve.FieldLength), isUnsigned: true, isBigEndian: true), new BigInteger(publicKey.AsSpan(1 + curve.FieldLength), isUnsigned: true, isBigEndian: true));
		CurvePoint? point = reference.Add(reference.Multiply(reference.Generator, e * w % n), reference.Multiply(q, r * w % n));
		return r > 0 && r < n && s > 0 && s < n && point is not null && point.X % n == r;
	}

	private static byte[] Integer(BigInteger value)
	{
		return Element(0x02, value.ToByteArray(isBigEndian: true));
	}

	private static byte[] Oid(string oid)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteObjectIdentifier(oid);
		return writer.Encode();
	}

	// Written here rather than by the code under test.
	private static byte[] Header(byte tag, int length)
	{
		return length switch
		{
			< 0x80 => [tag, (byte)length],
			< 0x100 => [tag, 0x81, (byte)length],
			_ => [tag, 0x82, (byte)(length >> 8), (byte)length]
		};
	}

	private static byte[] Element(byte tag, byte[] contents)
	{
		return [.. Header(tag, contents.Length), .. contents];
	}

	private static byte[] LongForm(byte tag, byte[] contents)
	{
		return contents.Length < 0x80 ? [tag, 0x81, (byte)contents.Length, .. contents] : [tag, 0x82, 0, (byte)contents.Length, .. contents];
	}

	private static byte[] AlgorithmIdentifier(string curveOid)
	{
		return Element(0x30, [.. Oid(EcPublicKeyOid), .. Oid(curveOid)]);
	}

	private static byte[] EcPrivateKey(int version, byte[] d, string? curveOid, byte[]? publicKey, byte[]? trailing = null)
	{
		List<byte> contents = [.. Element(0x02, [(byte)version]), .. Element(0x04, d)];

		if (curveOid is not null)
		{
			contents.AddRange(Element(0xA0, Oid(curveOid)));
		}

		if (publicKey is not null)
		{
			contents.AddRange(Element(0xA1, Element(0x03, [0, .. publicKey])));
		}

		contents.AddRange(trailing ?? []);
		return Element(0x30, [.. contents]);
	}

	private static byte[] Pkcs8(string curveOid, byte[] ecPrivateKey, byte[]? publicKey = null)
	{
		byte[] contents = [.. Element(0x02, [(byte)(publicKey is null ? 0 : 1)]), .. AlgorithmIdentifier(curveOid), .. Element(0x04, ecPrivateKey)];
		return Element(0x30, publicKey is null ? contents : [.. contents, .. Element(0x81, [0, .. publicKey])]);
	}
}
