using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Tests.EllipticCurves.Curve25519;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519TestUtils;
using static CryptoBase.Tests.Signatures.EdDsa.Ed25519TestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.EdDsa;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class Ed25519Test
{
	private const string Ed25519Oid = "1.3.101.112";

	private static readonly EdwardsValue[] Torsion = TorsionPoints();

	// The first element of Torsion of order 8.
	private static readonly EdwardsValue OrderEight = Torsion.First(point => Multiply(point, 4) != Identity);

	// RFC 8410 §10.1 and §10.3: one key pair as a SubjectPublicKeyInfo, a version 1 PrivateKeyInfo, and a version 2 OneAsymmetricKey with an attribute and the public key.
	private const string Rfc8410PublicKey = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
	private const string Rfc8410PrivateKey = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
	private const string Rfc8410PrivateKeyWithPublicKey = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

	[Test]
	public async Task LengthsAreFixed()
	{
		using Ed25519 key = Ed25519.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That((Ed25519.PrivateKeyLength, Ed25519.PublicKeyLength, Ed25519.SignatureLength, Ed25519.MaxContextLength)).IsEqualTo((32, 32, 64, 255));
			await Assert.That((key.SubjectPublicKeyInfoLength, key.Pkcs8PrivateKeyLength)).IsEqualTo((44, 48));
			await Assert.That(key.GetMaxSignatureLength(SignatureAlgorithm.Ed25519)).IsEqualTo(64);
		}
	}

	// Seeds and messages around the SHA-512 block, which the prefix, R ‖ A and dom2 shift, in every variant and with contexts of 1 to 255 bytes.
	[Test]
	public async Task SignaturesMatchTheReference()
	{
		Random random = new(1);
		List<string> failures = [];

		for (int i = 0; i < 6; ++i)
		{
			byte[] seed = new byte[Ed25519.PrivateKeyLength];
			random.NextBytes(seed);
			using Ed25519 key = Ed25519.ImportPrivateKey(seed);
			using Ed25519 verifier = Ed25519.ImportPublicKey(Ed25519Reference.PublicKey(seed));

			if (!ExportPrivateKey(key).AsSpan().SequenceEqual(seed) || !ExportPublicKey(key).AsSpan().SequenceEqual(Ed25519Reference.PublicKey(seed)))
			{
				failures.Add($"keys of seed {Convert.ToHexString(seed)}");
			}

			foreach (int messageLength in (int[])[0, 1, 31, 32, 63, 64, 95, 96, 111, 112, 127, 128, 129, 1000])
			{
				byte[] message = new byte[messageLength];
				random.NextBytes(message);
				byte[] context = new byte[(messageLength * 7 + i) % 255 + 1];
				random.NextBytes(context);

				foreach (Ed25519Variant variant in Enum.GetValues<Ed25519Variant>())
				{
					byte[] variantContext = variant is Ed25519Variant.Pure ? [] : context;
					byte[] expected = Ed25519Reference.Sign(seed, Ed25519Reference.Input(variant, message), Ed25519Reference.Domain(variant, variantContext));

					if (!Sign(key, variant, message, variantContext).AsSpan().SequenceEqual(expected) || !Verify(verifier, variant, message, expected, variantContext))
					{
						failures.Add($"{variant}, seed {Convert.ToHexString(seed)}, message of {messageLength} bytes");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task SigningIsDeterministic()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		using Ed25519 copy = Ed25519.ImportPrivateKey(ExportPrivateKey(key));
		byte[] message = CreateDeterministicSource(50);
		byte[] signature = Sign(key, SignatureAlgorithm.Ed25519, message);

		using (Assert.Multiple())
		{
			await Assert.That(Sign(key, SignatureAlgorithm.Ed25519, message)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(Sign(copy, SignatureAlgorithm.Ed25519, message)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(Sign(copy, Ed25519Variant.Pure, message, [])).IsEquivalentTo(signature, CollectionOrdering.Matching);
		}
	}

	// Encodings with y of p or more, x = 0 with the sign bit set, or a y with no x.
	[Test]
	public async Task PublicKeysThatDoNotDecodeThrow()
	{
		BigInteger nonSquare = 2;

		while (IsSquare((nonSquare * nonSquare - 1) * Inverse(D * nonSquare * nonSquare + 1)))
		{
			++nonSquare;
		}

		byte[][] encodings =
		[
			EncodeInteger(P), EncodeInteger(P + 1), EncodeInteger(P + 2), EncodeInteger((BigInteger.One << 255) - 1), WithSignBit(EncodeInteger(1)), WithSignBit(EncodeInteger(P - 1)),
			EncodeInteger(nonSquare), WithSignBit(EncodeInteger(nonSquare))
		];

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in encodings)
			{
				await Assert.That(Decode(encoding)).IsNull().Because(Convert.ToHexString(encoding));
				await Assert.That(() => Ed25519.ImportPublicKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
				await Assert.That(() => Ed25519.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo(encoding))).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
			}

			foreach (int length in (int[])[0, 31, 33])
			{
				await Assert.That(() => Ed25519.ImportPublicKey(new byte[length])).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => Ed25519.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo(new byte[length]))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => Ed25519.ImportPrivateKey(new byte[length])).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	// Each of the eight points of small order is a public key, and a signature that meets the equation for it verifies. With such a key, [k]A takes at most 8 values whatever the message, so a signature also verifies for other messages, as the reference decides.
	[Test]
	public async Task SmallOrderPublicKeysVerify()
	{
		Random random = new(2);
		List<string> failures = [];

		foreach (EdwardsValue point in Torsion)
		{
			byte[] publicKey = Encode(point);
			(byte[] message, byte[] signature) = SignForTorsionKey(random, point);
			byte[][] otherMessages = [.. Enumerable.Range(0, message.Length).Select(i => Flip(message, i))];
			using Ed25519 first = Ed25519.ImportPublicKey(publicKey);
			using Ed25519 later = Ed25519.ImportPublicKey(publicKey);
			bool verified = first.Verify(message, signature) && Ed25519Reference.Verify(publicKey, message, signature, []);

			for (int i = 0; i < 3; ++i)
			{
				verified &= later.Verify(message, signature);
			}

			foreach (byte[] other in otherMessages)
			{
				verified &= later.Verify(other, signature) == Ed25519Reference.Verify(publicKey, other, signature, []);
			}

			if (!verified || !ExportPublicKey(first).AsSpan().SequenceEqual(publicKey))
			{
				failures.Add(Show(point));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// R of small order: the identity, with S = k·s for a key of prime order, and for a key with a torsion part T, R = −[k]T with S = k·a.
	[Test]
	public async Task SmallOrderNoncesVerify()
	{
		Random random = new(3);
		byte[] seed = new byte[Ed25519.PrivateKeyLength];
		random.NextBytes(seed);
		byte[] publicKey = Ed25519Reference.PublicKey(seed);
		byte[] message = CreateDeterministicSource(20);
		byte[] identityR = Encode(Identity);
		BigInteger k = Ed25519Reference.HashToScalar([], [.. identityR, .. publicKey], message);
		byte[] identitySignature = Ed25519Reference.Signature(identityR, k * Ed25519Reference.Expand(seed).Scalar % L);
		(byte[] mixedPublicKey, byte[] mixedMessage, byte[] mixedSignature) = SignWithTorsionNonce(random);
		using Ed25519 key = Ed25519.ImportPublicKey(publicKey);
		using Ed25519 mixed = Ed25519.ImportPublicKey(mixedPublicKey);

		using (Assert.Multiple())
		{
			await Assert.That(Decode(mixedSignature.AsSpan(0, 32)) is { } r && Multiply(r, 8) == Identity && r != Identity).IsTrue();
			await Assert.That(Ed25519Reference.Verify(publicKey, message, identitySignature, [])).IsTrue();
			await Assert.That(Ed25519Reference.Verify(mixedPublicKey, mixedMessage, mixedSignature, [])).IsTrue();

			for (int i = 0; i < 3; ++i)
			{
				await Assert.That(key.Verify(message, identitySignature)).IsTrue().Because($"verification {i}");
				await Assert.That(mixed.Verify(mixedMessage, mixedSignature)).IsTrue().Because($"verification {i}");
			}
		}
	}

	// The identity as R in its two other encodings: y = p + 1, and y = 1 with the sign bit, as x = 0. Each S meets the group equation for its own R bytes, so only the comparison of the encodings rejects them.
	[Test]
	public async Task NonCanonicalNoncesFail()
	{
		Random random = new(4);
		byte[] seed = new byte[Ed25519.PrivateKeyLength];
		random.NextBytes(seed);
		BigInteger s = Ed25519Reference.Expand(seed).Scalar;
		byte[] publicKey = Ed25519Reference.PublicKey(seed);
		byte[] message = CreateDeterministicSource(20);
		using Ed25519 key = Ed25519.ImportPublicKey(publicKey);
		byte[][] encodings = [Encode(Identity), EncodeInteger(P + 1), WithSignBit(EncodeInteger(1))];
		bool[] verified = new bool[encodings.Length];

		for (int i = 0; i < encodings.Length; ++i)
		{
			BigInteger k = Ed25519Reference.HashToScalar([], [.. encodings[i], .. publicKey], message);
			byte[] signature = Ed25519Reference.Signature(encodings[i], k * s % L);
			verified[i] = key.Verify(message, signature) | key.Verify(message, signature) | key.Verify(message, signature);
		}

		await Assert.That(verified).IsEquivalentTo([true, false, false], CollectionOrdering.Matching);
	}

	// S + jL meets the group equation whenever S does, so only the range check rejects it.
	[Test]
	public async Task MalleatedSignaturesFail()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		using Ed25519 verifier = Ed25519.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(30);
		byte[] signature = Sign(key, SignatureAlgorithm.Ed25519, message);
		BigInteger s = DecodeInteger(signature.AsSpan(32));
		List<BigInteger> malleated = [L, (BigInteger.One << 256) - 1];

		for (BigInteger multiple = s + L; multiple < BigInteger.One << 256; multiple += L)
		{
			malleated.Add(multiple);
		}

		List<string> accepted = [];

		foreach (BigInteger value in malleated)
		{
			byte[] other = Ed25519Reference.Signature(signature.AsSpan(0, 32), value);

			for (int i = 0; i < 3; ++i)
			{
				if (verifier.Verify(message, other))
				{
					accepted.Add($"{value:X}");
				}
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(malleated.Count).IsEqualTo(17);
			await Assert.That(accepted).IsEmpty();
			await Assert.That(verifier.Verify(message, signature)).IsTrue();
		}
	}

	// A signature verifies only with the variant and context that made it; Ed25519ctx needs a context, and an empty one selects Ed25519.
	[Test]
	public async Task VariantsAndContextsSeparate()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		byte[] message = CreateDeterministicSource(40);
		byte[] a = "a"u8.ToArray();
		byte[] b = "b"u8.ToArray();
		(Ed25519Variant Variant, byte[] Context)[] cases = [(Ed25519Variant.Pure, []), (Ed25519Variant.Context, a), (Ed25519Variant.Context, b), (Ed25519Variant.PreHash, []), (Ed25519Variant.PreHash, a)];
		byte[][] signatures = [.. cases.Select(c => Sign(key, c.Variant, message, c.Context))];
		List<string> wrong = [];

		for (int i = 0; i < cases.Length; ++i)
		{
			for (int j = 0; j < cases.Length; ++j)
			{
				if (Verify(key, cases[j].Variant, message, signatures[i], cases[j].Context) != (i == j))
				{
					wrong.Add($"signature {i} with case {j}");
				}
			}
		}

		byte[] hash = SHA512.HashData(message);

		using (Assert.Multiple())
		{
			await Assert.That(wrong).IsEmpty();
			await Assert.That(signatures.Distinct(new ByteArrayComparer()).Count()).IsEqualTo(cases.Length);
			await Assert.That(Sign(key, Ed25519Variant.Context, message, [])).IsEquivalentTo(signatures[0], CollectionOrdering.Matching);
			await Assert.That(key.Verify(hash, signatures[3])).IsFalse();
			await Assert.That(key.VerifyPreHash(hash, signatures[0])).IsFalse();
		}
	}

	[Test]
	public async Task InvalidArgumentsThrow()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		using Ed25519 publicOnly = Ed25519.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(10);
		byte[] hash = SHA512.HashData(message);
		byte[] longContext = new byte[256];
		byte[] signature = CreateGuardedBuffer(0, Ed25519.SignatureLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => key.Sign(message, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");
			await Assert.That(() => key.Verify(message, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");
			await Assert.That(() => key.SignPreHash(hash, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");
			await Assert.That(() => key.VerifyPreHash(hash, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");

			foreach (int length in (int[])[0, 63, 65])
			{
				byte[] wrongHash = new byte[length];
				await Assert.That(() => key.SignPreHash(wrongHash, signature)).Throws<ArgumentException>().WithParameterName("hash");
				await Assert.That(() => key.VerifyPreHash(wrongHash, signature)).Throws<ArgumentException>().WithParameterName("hash");
			}

			await Assert.That(() => key.Sign(message, new byte[Ed25519.SignatureLength - 1])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.SignPreHash(hash, new byte[Ed25519.SignatureLength - 1])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => publicOnly.Sign(message, signature)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.SignPreHash(hash, signature)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.ExportPrivateKey(new byte[Ed25519.PrivateKeyLength])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(signature).All(static value => value is DestinationSentinel);
			await Assert.That(key.Sign(message, signature, new byte[255])).IsEqualTo(Ed25519.SignatureLength);
		}
	}

	[Test]
	public async Task SignaturesOfTheWrongLengthFail()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		byte[] message = CreateDeterministicSource(10);
		byte[] hash = SHA512.HashData(message);
		byte[] signature = Sign(key, Ed25519Variant.Pure, message, []);
		byte[] preHashSignature = Sign(key, Ed25519Variant.PreHash, message, []);
		List<string> accepted = [];

		foreach (int delta in (int[])[-64, -1, 1, 32])
		{
			if (key.Verify(message, Resize(signature, delta)) || key.VerifyPreHash(hash, Resize(preHashSignature, delta)))
			{
				accepted.Add($"{delta}");
			}
		}

		await Assert.That(accepted).IsEmpty();
	}

	[Test]
	public async Task InputsMayOverlapTheSignature()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		byte[] message = CreateDeterministicSource(100);
		byte[] hash = SHA512.HashData(message);
		byte[] context = "context"u8.ToArray();
		List<string> failures = [];

		foreach (int offset in (int[])[0, 1, 63, 64])
		{
			byte[] buffer = new byte[offset + message.Length + Ed25519.SignatureLength];
			message.CopyTo(buffer, offset);
			key.Sign(buffer.AsSpan(offset, message.Length), buffer.AsSpan(0, Ed25519.SignatureLength), context);

			if (!key.Verify(message, buffer.AsSpan(0, Ed25519.SignatureLength), context))
			{
				failures.Add($"message at {offset}");
			}

			hash.CopyTo(buffer, offset);
			key.SignPreHash(buffer.AsSpan(offset, hash.Length), buffer.AsSpan(0, Ed25519.SignatureLength), context);

			if (!key.VerifyPreHash(hash, buffer.AsSpan(0, Ed25519.SignatureLength), context))
			{
				failures.Add($"hash at {offset}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The first verification with an instance goes without the table of its public key, and the later ones use it, so both must decide alike for keys of every order.
	[Test]
	public async Task FirstAndLaterVerificationsAgree()
	{
		Random random = new(5);
		byte[] seed = new byte[Ed25519.PrivateKeyLength];
		random.NextBytes(seed);
		(byte[] mixedPublicKey, byte[] mixedMessage, byte[] mixedSignature) = SignWithTorsionNonce(random);
		(byte[] torsionMessage, byte[] torsionSignature) = SignForTorsionKey(random, OrderEight);
		List<(byte[] PublicKey, byte[] Message, byte[] Signature)> cases = [(mixedPublicKey, mixedMessage, mixedSignature), (Encode(OrderEight), torsionMessage, torsionSignature)];
		byte[] publicKey = Ed25519Reference.PublicKey(seed);

		for (int i = 0; i < 4; ++i)
		{
			byte[] message = new byte[i * 37];
			random.NextBytes(message);
			cases.Add((publicKey, message, Ed25519Reference.Sign(seed, message, [])));
			cases.Add((mixedPublicKey, message, Ed25519Reference.Sign(seed, message, [])));
		}

		foreach (BigInteger s in (BigInteger[])[0, 1, L - 1])
		{
			cases.Add((publicKey, mixedMessage, Ed25519Reference.Signature(Encode(Multiply(Base, RandomBelow(random, L))), s)));
		}

		// Each case also with the next message, which the signature does not fit.
		int count = cases.Count;

		for (int i = 0; i < count; ++i)
		{
			cases.Add(cases[i] with { Message = cases[(i + 1) % count].Message });
		}

		bool[] expected = [.. cases.Select(static c => Ed25519Reference.Verify(c.PublicKey, c.Message, c.Signature, []))];
		Dictionary<string, Ed25519> later = [];
		List<string> failures = [];

		try
		{
			foreach (byte[] key in cases.Select(static c => c.PublicKey).Distinct(new ByteArrayComparer()))
			{
				Ed25519 instance = Ed25519.ImportPublicKey(key);
				later[Convert.ToHexString(key)] = instance;
				_ = instance.Verify([], new byte[Ed25519.SignatureLength]) | instance.Verify([], new byte[Ed25519.SignatureLength]);
			}

			for (int i = 0; i < cases.Count; ++i)
			{
				(byte[] key, byte[] message, byte[] signature) = cases[i];
				using Ed25519 first = Ed25519.ImportPublicKey(key);

				if (first.Verify(message, signature) != expected[i] || later[Convert.ToHexString(key)].Verify(message, signature) != expected[i])
				{
					failures.Add($"case {i}, expected {expected[i]}");
				}
			}
		}
		finally
		{
			foreach (Ed25519 instance in later.Values)
			{
				instance.Dispose();
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
	public async Task ConcurrentVerificationsWithANewInstanceAgree()
	{
		const int threadCount = 8;
		using Ed25519 signer = Ed25519.GenerateKey();
		byte[] publicKey = ExportPublicKey(signer);
		byte[] message = CreateDeterministicSource(30);
		byte[] other = CreateDeterministicSource(31);
		byte[] signature = Sign(signer, SignatureAlgorithm.Ed25519, message);
		int failures = 0;

		for (int round = 0; round < 4; ++round)
		{
			using Ed25519 key = Ed25519.ImportPublicKey(publicKey);
			using Barrier barrier = new(threadCount);
			Task[] tasks = new Task[threadCount];

			for (int i = 0; i < tasks.Length; ++i)
			{
				tasks[i] = Task.Factory.StartNew(() =>
				{
					barrier.SignalAndWait();

					for (int k = 0; k < 4; ++k)
					{
						if (!key.Verify(message, signature) || key.Verify(other, signature))
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

	[Test]
	public async Task ConcurrentSignaturesAgree()
	{
		const int threadCount = 8;
		using Ed25519 key = Ed25519.GenerateKey();
		byte[][] messages = [.. Enumerable.Range(0, threadCount).Select(CreateDeterministicSource)];
		byte[][] expected = [.. messages.Select(message => Sign(key, SignatureAlgorithm.Ed25519, message))];
		using Barrier barrier = new(threadCount);
		int failures = 0;
		Task[] tasks = new Task[threadCount];

		for (int i = 0; i < tasks.Length; ++i)
		{
			int index = i;
			tasks[i] = Task.Factory.StartNew(() =>
			{
				barrier.SignalAndWait();

				for (int k = 0; k < 16; ++k)
				{
					byte[] signature = Sign(key, SignatureAlgorithm.Ed25519, messages[index]);

					if (!signature.AsSpan().SequenceEqual(expected[index]) || !key.Verify(messages[index], signature))
					{
						Interlocked.Increment(ref failures);
					}
				}
			}, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
		}

		await Task.WhenAll(tasks);
		await Assert.That(failures).IsZero();
	}

	[Test]
	public async Task Rfc8410ExamplesImport()
	{
		byte[] subjectPublicKeyInfo = Convert.FromBase64String(Rfc8410PublicKey);
		byte[] privateKey = Convert.FromBase64String(Rfc8410PrivateKey);
		byte[] seed = Convert.FromHexString("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");
		byte[] publicKey = Convert.FromHexString("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");
		using Ed25519 fromPublicKey = Ed25519.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using Ed25519 fromPrivateKey = Ed25519.ImportPkcs8PrivateKey(privateKey);
		using Ed25519 fromPrivateKeyWithPublicKey = Ed25519.ImportPkcs8PrivateKey(Convert.FromBase64String(Rfc8410PrivateKeyWithPublicKey));
		using ISignatureKey fromPublicPem = SignatureKey.ImportFromPem($"-----BEGIN PUBLIC KEY-----\n{Rfc8410PublicKey}\n-----END PUBLIC KEY-----\n");
		using ISignatureKey fromPrivatePem = SignatureKey.ImportFromPem($"-----BEGIN PRIVATE KEY-----\n{Rfc8410PrivateKeyWithPublicKey}\n-----END PRIVATE KEY-----\n");
		byte[] message = "message"u8.ToArray();
		byte[] signature = Sign(fromPrivatePem, SignatureAlgorithm.Ed25519, message);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(fromPublicKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(fromPublicKey)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);

			foreach (Ed25519 key in (Ed25519[])[fromPrivateKey, fromPrivateKeyWithPublicKey])
			{
				await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(seed, CollectionOrdering.Matching);
				await Assert.That(ExportPublicKey(key)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			}

			await Assert.That(fromPublicPem).IsTypeOf<Ed25519>();
			await Assert.That(fromPrivatePem).IsTypeOf<Ed25519>();
			await Assert.That(fromPublicPem.Verify(SignatureAlgorithm.Ed25519, message, signature)).IsTrue();
		}
	}

	[Test]
	public async Task Pkcs8ImportAcceptsOptionalPartsThatMatch()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		byte[] seed = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(key);
		byte[] expected = ExportPkcs8PrivateKey(key);
		byte[] attributes = Tlv(0xA0, Sequence(Oid("1.2.840.113549.1.9.9.20"), Tlv(0x31, Tlv(0x0C, "name"u8.ToArray()))));
		byte[][] encodings =
		[
			Pkcs8(0, CurvePrivateKey(seed)), Pkcs8(0, CurvePrivateKey(seed), attributes), Pkcs8(1, CurvePrivateKey(seed)), Pkcs8(1, CurvePrivateKey(seed), PublicKeyField(publicKey)),
			Pkcs8(1, CurvePrivateKey(seed), attributes, PublicKeyField(publicKey))
		];

		using (Assert.Multiple())
		{
			await Assert.That(encodings[0]).IsEquivalentTo(expected, CollectionOrdering.Matching);

			foreach (byte[] encoding in encodings)
			{
				using Ed25519 imported = Ed25519.ImportPkcs8PrivateKey(encoding);
				await Assert.That(ExportPkcs8PrivateKey(imported)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(Convert.ToHexString(encoding));
			}
		}
	}

	[Test]
	public async Task Pkcs8ImportRejectsInvalidKeys()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		using Ed25519 other = Ed25519.GenerateKey();
		byte[] seed = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(key);
		byte[] curvePrivateKey = CurvePrivateKey(seed);
		byte[][] invalid =
		[
			// A public key that does not match, of the wrong length, with unused bits, or not in a primitive [1].
			Pkcs8(1, curvePrivateKey, PublicKeyField(ExportPublicKey(other))), Pkcs8(1, curvePrivateKey, PublicKeyField(publicKey.AsSpan(1).ToArray())), Pkcs8(1, curvePrivateKey, PublicKeyField([.. publicKey, 0])),
			Pkcs8(1, curvePrivateKey, Tlv(0x81, [1, .. publicKey])), Pkcs8(1, curvePrivateKey, Tlv(0xA1, Tlv(0x03, [0, .. publicKey]))), Pkcs8(0, curvePrivateKey, PublicKeyField(publicKey)),
			// A seed of the wrong length, not in a CurvePrivateKey, or not in DER.
			Pkcs8(0, CurvePrivateKey(seed.AsSpan(1).ToArray())), Pkcs8(0, CurvePrivateKey([.. seed, 0])), Pkcs8(0, seed), Pkcs8(0, [0x03, 0x20, .. seed]), Pkcs8(0, [0x04, 0x81, 0x20, .. seed]),
			Pkcs8(0, [.. curvePrivateKey, 0x05, 0x00]), Pkcs8(0, []),
			// Another version or algorithm.
			Pkcs8(2, curvePrivateKey), Sequence([0x02, 0x01, 0x00], Sequence(Oid(Ed25519Oid), [0x05, 0x00]), Tlv(0x04, curvePrivateKey)), Sequence([0x02, 0x01, 0x00], Sequence(Oid("1.3.101.110")), Tlv(0x04, curvePrivateKey)),
			// RFC 8410 §10.3: a key in BER, and keys whose public key, under an explicit [1], is a byte short.
			Convert.FromBase64String("MIACAQAwgAYDK2VwAAAEIgQg1O5y2/kTWErVttjx92n4rTr+fCjL8dT74Jeoj0R1WEIAAA=="),
			Convert.FromBase64String("MFICAQEwBQYDK2VwBCIEIC3GfeUYbZGTAhwLEE2cbvJL7ivTlcy17VottfN6L8HwoSIDIADBfk2Lv/J8H7YYwj/OmIcDx++jzVkKrKwS0/HjyQyM"),
			Convert.FromBase64String("MFICAQEwBQYDK2VwBCIEILJXn1VaLqvausjUaZexwI/ozmOFjfEk78KcYN+7hsNJoSIDIACdQhJwzi/MCGcsQeQnIUh2JFybDxSrZxuLudJmpJLk")
		];

		using (Assert.Multiple())
		{
			for (int i = 0; i < invalid.Length; ++i)
			{
				byte[] encoding = invalid[i];
				await Assert.That(() => Ed25519.ImportPkcs8PrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because($"case {i}");
			}
		}
	}

	[Test]
	public async Task FailedPkcs8ImportErasesTheKey()
	{
		using Ed25519 key = Ed25519.GenerateKey();
		using Ed25519 other = Ed25519.GenerateKey();
		byte[] encoding = Pkcs8(1, CurvePrivateKey(ExportPrivateKey(key)), PublicKeyField(ExportPublicKey(other)));
		Ed25519Key core = default;

		ArgumentException? exception = null;

		try
		{
			core.ImportPkcs8PrivateKey(encoding);
		}
		catch (ArgumentException e)
		{
			exception = e;
		}

		await Assert.That(exception).IsNotNull();
		await Assert.That(IsErased(ref core)).IsTrue();
	}

	// Clear, as disposal calls it, leaves nothing of the seed, the scalar, the prefix, the public key or the table.
	[Test]
	public async Task ClearErasesTheKey()
	{
		byte[] message = CreateDeterministicSource(10);
		Ed25519Key core = default;
		core.GenerateKey();
		byte[] signature = new byte[Ed25519.SignatureLength];
		core.Sign(message, [], signature);
		bool verified = core.Verify(message, signature, []) & core.Verify(message, signature, []);
		core.Clear();

		using (Assert.Multiple())
		{
			await Assert.That(verified).IsTrue();
			await Assert.That(IsErased(ref core)).IsTrue();
		}
	}

	// The table belongs to the public key, so whatever replaces the key must drop it: otherwise the new key would verify as the old one.
	[Test]
	public async Task ReplacingTheKeyDropsTheTable()
	{
		using Ed25519 first = Ed25519.GenerateKey();
		using Ed25519 second = Ed25519.GenerateKey();
		byte[] message = CreateDeterministicSource(20);
		byte[] firstPublicKey = ExportPublicKey(first);
		byte[] firstSignature = Sign(first, SignatureAlgorithm.Ed25519, message);
		byte[] secondSignature = Sign(second, SignatureAlgorithm.Ed25519, message);
		byte[] secondPublicKey = ExportPublicKey(second);
		byte[] secondPrivateKey = ExportPrivateKey(second);
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(second);
		byte[] pkcs8 = ExportPkcs8PrivateKey(second);
		List<string> failures = [];

		for (int i = 0; i < 5; ++i)
		{
			Ed25519Key core = default;
			core.ImportPublicKey(firstPublicKey);
			bool verified = core.Verify(message, firstSignature, []) & core.Verify(message, firstSignature, []);

			switch (i)
			{
				case 0:
					core.ImportPublicKey(secondPublicKey);
					break;
				case 1:
					core.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
					break;
				case 2:
					core.ImportPrivateKey(secondPrivateKey);
					break;
				case 3:
					core.ImportPkcs8PrivateKey(pkcs8);
					break;
				default:
					core.GenerateKey();
					break;
			}

			for (int k = 0; k < 3; ++k)
			{
				verified &= !core.Verify(message, firstSignature, []) && (i is 4 || core.Verify(message, secondSignature, []));
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
	public async Task DisposedInstancesThrow()
	{
		Ed25519 key = Ed25519.GenerateKey();
		byte[] message = CreateDeterministicSource(10);
		byte[] hash = SHA512.HashData(message);
		byte[] signature = Sign(key, SignatureAlgorithm.Ed25519, message);
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.ExportPrivateKey(new byte[Ed25519.PrivateKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPublicKey(new byte[Ed25519.PublicKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Sign(message, new byte[Ed25519.SignatureLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Verify(message, signature)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.SignPreHash(hash, new byte[Ed25519.SignatureLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.VerifyPreHash(hash, signature)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	// Background GC can overcount unused allocation-context space, causing intermittent allocation assertion failures.
	// https://github.com/dotnet/runtime/pull/134855
	public async Task SigningAndVerificationDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan<ulong>, such as the curve constants, allocates a field handle.
		SkipUnlessOptimized<Ed25519>();

		using Ed25519 key = Ed25519.GenerateKey();
		using Ed25519 verifier = Ed25519.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(100);
		byte[] hash = SHA512.HashData(message);
		byte[] context = "context"u8.ToArray();
		byte[] signature = new byte[Ed25519.SignatureLength];

		// The second verification with key allocates the table of its public key before the count starts; within the count, key verifies with that table and verifier for the first time, without one.
		bool valid = Exercise(key, message, hash, context, signature) & Exercise(key, message, hash, context, signature);
		key.Sign(message, signature);
		long before = GC.GetAllocatedBytesForCurrentThread();
		valid &= verifier.Verify(message, signature);
		valid &= Exercise(key, message, hash, context, signature);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(valid).IsTrue();
		}

		static bool Exercise(Ed25519 key, byte[] message, byte[] hash, byte[] context, byte[] signature)
		{
			key.Sign(SignatureAlgorithm.Ed25519, message, signature);
			bool valid = key.Verify(SignatureAlgorithm.Ed25519, message, signature);
			key.Sign(message, signature, context);
			valid &= key.Verify(message, signature, context);
			key.SignPreHash(hash, signature, context);
			return valid & key.VerifyPreHash(hash, signature, context);
		}
	}

	// A message and a signature for the public key point, of order dividing 8: [S]B − [k]A = R holds for R = [S]B − [j]A when [k]A = [j]A, which the search finds by trying j for one message after another.
	private static (byte[] Message, byte[] Signature) SignForTorsionKey(Random random, EdwardsValue point)
	{
		byte[] publicKey = Encode(point);
		BigInteger s = RandomBelow(random, L);
		EdwardsValue sB = Multiply(Base, s);

		for (int counter = 0; ; ++counter)
		{
			byte[] message = BitConverter.GetBytes(counter);

			for (int j = 0; j < 8; ++j)
			{
				byte[] encodedR = Encode(Add(sB, Negate(Multiply(point, j))));
				BigInteger k = Ed25519Reference.HashToScalar([], [.. encodedR, .. publicKey], message);

				if (Multiply(point, k % 8) == Multiply(point, j))
				{
					return (message, Ed25519Reference.Signature(encodedR, s));
				}
			}
		}
	}

	// A public key A = [a]B + T for T of order 8, and a signature whose R = −[j]T has a small order other than 1: with S = k·a, [S]B − [k]A = −[k]T, so k ≡ j (mod 8) is needed.
	private static (byte[] PublicKey, byte[] Message, byte[] Signature) SignWithTorsionNonce(Random random)
	{
		BigInteger a = RandomBelow(random, L);
		byte[] publicKey = Encode(Add(Multiply(Base, a), OrderEight));

		for (int counter = 0; ; ++counter)
		{
			byte[] message = BitConverter.GetBytes(counter);

			for (int j = 1; j < 8; ++j)
			{
				byte[] encodedR = Encode(Negate(Multiply(OrderEight, j)));
				BigInteger k = Ed25519Reference.HashToScalar([], [.. encodedR, .. publicKey], message);

				if (k % 8 == j)
				{
					return (publicKey, message, Ed25519Reference.Signature(encodedR, k * a % L));
				}
			}
		}
	}

	private static byte[] WithSignBit(byte[] encoding)
	{
		encoding[31] |= 0x80;
		return encoding;
	}

	private static byte[] SubjectPublicKeyInfo(byte[] publicKey)
	{
		return Sequence(Sequence(Oid(Ed25519Oid)), Tlv(0x03, [0, .. publicKey]));
	}

	private static byte[] CurvePrivateKey(byte[] seed)
	{
		return Tlv(0x04, seed);
	}

	// [1] IMPLICIT BIT STRING with no unused bits.
	private static byte[] PublicKeyField(byte[] publicKey)
	{
		return Tlv(0x81, [0, .. publicKey]);
	}

	private static byte[] Pkcs8(int version, byte[] privateKey, params byte[][] optional)
	{
		return Sequence([[0x02, 0x01, (byte)version], Sequence(Oid(Ed25519Oid)), Tlv(0x04, privateKey), .. optional]);
	}

	private static bool IsErased(ref Ed25519Key key)
	{
		return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<Ed25519Key, byte>(ref key), Unsafe.SizeOf<Ed25519Key>()).IndexOfAnyExcept((byte)0) < 0;
	}

	private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
	{
		public bool Equals(byte[]? x, byte[]? y)
		{
			return x.AsSpan().SequenceEqual(y);
		}

		public int GetHashCode(byte[] obj)
		{
			HashCode hash = new();
			hash.AddBytes(obj);
			return hash.ToHashCode();
		}
	}
}
