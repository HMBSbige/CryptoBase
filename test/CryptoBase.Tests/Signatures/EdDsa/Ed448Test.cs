using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Tests.EllipticCurves.Curve448;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448TestUtils;
using static CryptoBase.Tests.Signatures.EdDsa.Ed448TestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.EdDsa;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class Ed448Test
{
	private const string Ed448Oid = "1.3.101.113";

	private static readonly EdwardsValue[] Torsion = TorsionPoints();

	private static readonly EdwardsValue OrderFour = Torsion.First(point => Multiply(point, 2) != Identity);

	// SignatureAlgorithm.Ed448 signs with an empty context.
	private static readonly byte[] EmptyContextDomain = Ed448Reference.Domain(Ed448Variant.Pure, []);

	private const string ExternalPrivateKey = "MEcCAQAwBQYDK2VxBDsEOVCvBbs6sXR/rYDy55PE0O1uK8atUuudPpOMrliWz/q+Qjn0Nq7LtGqecLJdi7a08VrIOq7CcgPGjQ==";
	private const string ExternalPublicKey = "MEMwBQYDK2VxAzoA4MIsKOdn5zG3w74URj0t9qpLUBaOg/lnHzKXJFgxOKaCXQmJ18i8w+h3Bjdh//iBzfqOdTrJvl+A";
	private const string ExternalSignature = "D9E46C09B0795BB996F3D7C5EB52259E89FD1066AE49C60F74D97ACDBA32BA4DEE2C5B841AA9FEC95DED39A1407C2D5D56C1344F270FAD4F002769447784B87BBCDDCEA0A9A0A9C14C7AA6FB17D12F12CB3124A163DA1DB672F9B7DE6C6721E85191274D6DD97D1B63901C7E8C2BBB7E2900";
	private const string ExternalContextSignature = "808DE1494654E861ABB0A2682F23C70D1DDDF671FEFC146697B79E30EA68E00CFD74D3191973DC8FE84A24E5921D3EF50D89F196A9B0343F80434B6B6A23431DBBB34920773C698248B6AAFC5E595B57E93A8D985DD2CFC04478D3A0AEFACC957A97BFA25AF1F37B8C87619E032CB9C62100";
	private const string ExternalPreHashSignature = "D50FB2444E7D0DA6D1DA664BC1E7788C7616B3FB3C4186FF8130C6D4C66846F4AEFFB4F87AFEB94CB4F72176A4F4A521C99FAD1A8BE27A7900BE97A339BE219539FAAF0FD2E0EEF28B9B66FB2DC78215E948287DA986FA4A4C84F0B21436E32C96EB84C606D669EA1228A52FC8321DE32600";

	[Test]
	public async Task LengthsAreFixed()
	{
		using Ed448 key = Ed448.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That((Ed448.PrivateKeyLength, Ed448.PublicKeyLength, Ed448.SignatureLength, Ed448.MaxContextLength)).IsEqualTo((57, 57, 114, 255));
			await Assert.That((key.SubjectPublicKeyInfoLength, key.Pkcs8PrivateKeyLength)).IsEqualTo((69, 73));
			await Assert.That(key.GetMaxSignatureLength(SignatureAlgorithm.Ed448)).IsEqualTo(114);
		}
	}

	// Message lengths around the 136-byte SHAKE256 block, which the prefix, R ‖ A and dom4 shift.
	[Test]
	public async Task SignaturesMatchTheReference()
	{
		Random random = new(1);
		List<string> failures = [];

		for (int i = 0; i < 4; ++i)
		{
			byte[] seed = new byte[Ed448.PrivateKeyLength];
			random.NextBytes(seed);
			byte[] publicKey = Ed448Reference.PublicKey(seed);
			using Ed448 key = Ed448.ImportPrivateKey(seed);
			using Ed448 verifier = Ed448.ImportPublicKey(publicKey);

			if (!ExportPrivateKey(key).AsSpan().SequenceEqual(seed) || !ExportPublicKey(key).AsSpan().SequenceEqual(publicKey))
			{
				failures.Add($"keys of seed {Convert.ToHexString(seed)}");
			}

			foreach (int messageLength in (int[])[0, 1, 11, 12, 68, 69, 135, 136, 137, 204, 205, 272, 273, 1000])
			{
				byte[] message = new byte[messageLength];
				random.NextBytes(message);
				byte[] context = new byte[i % 2 is 0 ? 0 : (messageLength * 7 + i) % 256];
				random.NextBytes(context);

				foreach (Ed448Variant variant in Enum.GetValues<Ed448Variant>())
				{
					byte[] expected = Ed448Reference.Sign(seed, Ed448Reference.Input(variant, message), Ed448Reference.Domain(variant, context));

					if (!Sign(key, variant, message, context).AsSpan().SequenceEqual(expected) || !Verify(verifier, variant, message, expected, context))
					{
						failures.Add($"{variant}, seed {Convert.ToHexString(seed)}, message of {messageLength} bytes, context of {context.Length}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task SigningIsDeterministic()
	{
		using Ed448 key = Ed448.GenerateKey();
		using Ed448 copy = Ed448.ImportPrivateKey(ExportPrivateKey(key));
		byte[] message = CreateDeterministicSource(50);
		byte[] signature = Sign(key, SignatureAlgorithm.Ed448, message);

		using (Assert.Multiple())
		{
			await Assert.That(Sign(key, SignatureAlgorithm.Ed448, message)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(Sign(copy, SignatureAlgorithm.Ed448, message)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(Sign(copy, Ed448Variant.Pure, message, [])).IsEquivalentTo(signature, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task PublicKeysThatDoNotDecodeThrow()
	{
		BigInteger nonSquare = 2;

		while (IsSquare((nonSquare * nonSquare - 1) * Inverse(D * nonSquare * nonSquare - 1)))
		{
			++nonSquare;
		}

		byte[] basePoint = Encode(Base);
		byte[][] encodings =
		[
			EncodeInteger(P, 57), EncodeInteger(P + 1, 57), EncodeInteger(P + 2, 57), EncodeInteger((BigInteger.One << 448) - 1, 57), WithSignBit(EncodeInteger(1, 57)), WithSignBit(EncodeInteger(P - 1, 57)),
			EncodeInteger(nonSquare, 57), WithSignBit(EncodeInteger(nonSquare, 57)), WithLastByte(basePoint, 0x01), WithLastByte(basePoint, 0x40), WithLastByte(basePoint, 0xFF)
		];

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in encodings)
			{
				await Assert.That(Decode(encoding)).IsNull().Because(Convert.ToHexString(encoding));
				await Assert.That(() => Ed448.ImportPublicKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
				await Assert.That(() => Ed448.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo(encoding))).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
			}

			foreach (int length in (int[])[0, 56, 58])
			{
				await Assert.That(() => Ed448.ImportPublicKey(new byte[length])).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => Ed448.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo(new byte[length]))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => Ed448.ImportPrivateKey(new byte[length])).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	// [k]A takes at most 4 values, so a signature also verifies for other messages.
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
			using Ed448 first = Ed448.ImportPublicKey(publicKey);
			using Ed448 later = Ed448.ImportPublicKey(publicKey);
			bool verified = first.Verify(message, signature) && Ed448Reference.Verify(publicKey, message, signature, EmptyContextDomain);

			for (int i = 0; i < 3; ++i)
			{
				verified &= later.Verify(message, signature);
			}

			foreach (byte[] other in otherMessages)
			{
				verified &= later.Verify(other, signature) == Ed448Reference.Verify(publicKey, other, signature, EmptyContextDomain);
			}

			if (!verified || !ExportPublicKey(first).AsSpan().SequenceEqual(publicKey))
			{
				failures.Add(Show(point));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// R is the identity with S = k·s, or −[k]T with S = k·a for a key with torsion part T.
	[Test]
	public async Task SmallOrderNoncesVerify()
	{
		Random random = new(3);
		byte[] seed = new byte[Ed448.PrivateKeyLength];
		random.NextBytes(seed);
		byte[] publicKey = Ed448Reference.PublicKey(seed);
		byte[] message = CreateDeterministicSource(20);
		byte[] identityR = Encode(Identity);
		BigInteger k = Ed448Reference.HashToScalar(EmptyContextDomain, [.. identityR, .. publicKey], message);
		byte[] identitySignature = Ed448Reference.Signature(identityR, k * Ed448Reference.Expand(seed).Scalar % L);
		(byte[] mixedPublicKey, byte[] mixedMessage, byte[] mixedSignature) = SignWithTorsionNonce(random);
		using Ed448 key = Ed448.ImportPublicKey(publicKey);
		using Ed448 mixed = Ed448.ImportPublicKey(mixedPublicKey);

		using (Assert.Multiple())
		{
			await Assert.That(Decode(mixedSignature.AsSpan(0, 57)) is { } r && Multiply(r, 4) == Identity && r != Identity).IsTrue();
			await Assert.That(Ed448Reference.Verify(publicKey, message, identitySignature, EmptyContextDomain)).IsTrue();
			await Assert.That(Ed448Reference.Verify(mixedPublicKey, mixedMessage, mixedSignature, EmptyContextDomain)).IsTrue();

			for (int i = 0; i < 3; ++i)
			{
				await Assert.That(key.Verify(message, identitySignature)).IsTrue().Because($"verification {i}");
				await Assert.That(mixed.Verify(mixedMessage, mixedSignature)).IsTrue().Because($"verification {i}");
			}
		}
	}

	// Each S meets the group equation for its own R bytes, so only the comparison of the encodings rejects them.
	[Test]
	public async Task NonCanonicalNoncesFail()
	{
		Random random = new(4);
		byte[] seed = new byte[Ed448.PrivateKeyLength];
		random.NextBytes(seed);
		BigInteger s = Ed448Reference.Expand(seed).Scalar;
		byte[] publicKey = Ed448Reference.PublicKey(seed);
		byte[] message = CreateDeterministicSource(20);
		using Ed448 key = Ed448.ImportPublicKey(publicKey);
		byte[][] encodings = [Encode(Identity), EncodeInteger(P + 1, 57), WithSignBit(EncodeInteger(1, 57)), WithLastByte(EncodeInteger(1, 57), 0x01)];
		bool[] verified = new bool[encodings.Length];

		for (int i = 0; i < encodings.Length; ++i)
		{
			BigInteger k = Ed448Reference.HashToScalar(EmptyContextDomain, [.. encodings[i], .. publicKey], message);
			byte[] signature = Ed448Reference.Signature(encodings[i], k * s % L);
			verified[i] = key.Verify(message, signature) | key.Verify(message, signature) | key.Verify(message, signature);
		}

		await Assert.That(verified).IsEquivalentTo([true, false, false, false], CollectionOrdering.Matching);
	}

	// S + jL meets the group equation, so only the range check, including the 57th byte, rejects it.
	[Test]
	public async Task MalleatedSignaturesFail()
	{
		using Ed448 key = Ed448.GenerateKey();
		using Ed448 verifier = Ed448.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(30);
		byte[] signature = Sign(key, SignatureAlgorithm.Ed448, message);
		BigInteger s = DecodeInteger(signature.AsSpan(57));
		BigInteger two448 = BigInteger.One << 448;
		BigInteger two456 = BigInteger.One << 456;
		List<BigInteger> malleated = [L, two448 - 1, s + two448, s + (BigInteger.One << 455), two456 - 1];
		int belowTwo448 = 0;

		for (BigInteger multiple = s + L; multiple < two456; multiple += L)
		{
			malleated.Add(multiple);
			belowTwo448 += multiple < two448 ? 1 : 0;
		}

		List<string> accepted = [];

		foreach (BigInteger value in malleated)
		{
			byte[] other = Ed448Reference.Signature(signature.AsSpan(0, 57), value);

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
			await Assert.That(belowTwo448).IsEqualTo(3);
			await Assert.That(accepted).IsEmpty();
			await Assert.That(verifier.Verify(message, signature)).IsTrue();
		}
	}

	// [S]B − [k]A = R − [k]T, so the cofactorless equation holds only if 4 divides k.
	[Test]
	public async Task MixedOrderPublicKeysFollowTheCofactorlessEquation()
	{
		Random random = new(6);
		BigInteger a = RandomBelow(random, L);
		EdwardsValue point = Add(Multiply(Base, a), OrderFour);
		byte[] publicKey = Encode(point);
		using Ed448 later = Ed448.ImportPublicKey(publicKey);
		_ = later.Verify([], new byte[Ed448.SignatureLength]) | later.Verify([], new byte[Ed448.SignatureLength]);
		List<string> failures = [];
		(int Accepted, int Rejected) counts = (0, 0);

		for (int i = 0; i < 64 && (counts.Accepted < 2 || counts.Rejected < 2); ++i)
		{
			byte[] message = BitConverter.GetBytes(i);
			BigInteger r = RandomBelow(random, L);
			EdwardsValue nonce = Multiply(Base, r);
			byte[] encodedR = Encode(nonce);
			BigInteger k = Ed448Reference.HashToScalar(EmptyContextDomain, [.. encodedR, .. publicKey], message);
			BigInteger s = (r + k * a) % L;
			byte[] signature = Ed448Reference.Signature(encodedR, s);
			bool cofactorless = k % 4 == 0;
			bool cofactored = Multiply(Base, 4 * s) == Add(Multiply(nonce, 4), Multiply(point, 4 * k));
			using Ed448 first = Ed448.ImportPublicKey(publicKey);

			if (!cofactored || first.Verify(message, signature) != cofactorless || later.Verify(message, signature) != cofactorless || Ed448Reference.Verify(publicKey, message, signature, EmptyContextDomain) != cofactorless)
			{
				failures.Add($"message {i}, k mod 4 = {k % 4}");
			}

			counts = cofactorless ? (counts.Accepted + 1, counts.Rejected) : (counts.Accepted, counts.Rejected + 1);
		}

		using (Assert.Multiple())
		{
			await Assert.That(counts.Accepted).IsGreaterThanOrEqualTo(2);
			await Assert.That(counts.Rejected).IsGreaterThanOrEqualTo(2);
			await Assert.That(failures).IsEmpty();
		}
	}

	// Ed448 binds even an empty context.
	[Test]
	public async Task VariantsAndContextsSeparate()
	{
		using Ed448 key = Ed448.GenerateKey();
		byte[] message = CreateDeterministicSource(40);
		byte[] a = "a"u8.ToArray();
		byte[] b = "b"u8.ToArray();
		(Ed448Variant Variant, byte[] Context)[] cases = [(Ed448Variant.Pure, []), (Ed448Variant.Pure, a), (Ed448Variant.Pure, b), (Ed448Variant.PreHash, []), (Ed448Variant.PreHash, a)];
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

		byte[] hash = Ed448Reference.Input(Ed448Variant.PreHash, message);

		using (Assert.Multiple())
		{
			await Assert.That(wrong).IsEmpty();
			await Assert.That(signatures.Distinct(new ByteArrayComparer()).Count()).IsEqualTo(cases.Length);
			await Assert.That(Sign(key, SignatureAlgorithm.Ed448, message)).IsEquivalentTo(signatures[0], CollectionOrdering.Matching);
			await Assert.That(key.Verify(hash, signatures[3])).IsFalse();
			await Assert.That(key.VerifyPreHash(hash, signatures[0])).IsFalse();
		}
	}

	[Test]
	public async Task InvalidArgumentsThrow()
	{
		using Ed448 key = Ed448.GenerateKey();
		using Ed448 publicOnly = Ed448.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(10);
		byte[] hash = Ed448Reference.Input(Ed448Variant.PreHash, message);
		byte[] longContext = new byte[256];
		byte[] signature = CreateGuardedBuffer(0, Ed448.SignatureLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => key.Sign(message, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");
			await Assert.That(() => key.Verify(message, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");
			await Assert.That(() => key.SignPreHash(hash, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");
			await Assert.That(() => key.VerifyPreHash(hash, signature, longContext)).Throws<ArgumentException>().WithParameterName("context");

			foreach (int length in (int[])[0, 63, 65, 114])
			{
				byte[] wrongHash = new byte[length];
				await Assert.That(() => key.SignPreHash(wrongHash, signature)).Throws<ArgumentException>().WithParameterName("hash");
				await Assert.That(() => key.VerifyPreHash(wrongHash, signature)).Throws<ArgumentException>().WithParameterName("hash");
			}

			await Assert.That(() => key.Sign(message, new byte[Ed448.SignatureLength - 1])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.SignPreHash(hash, new byte[Ed448.SignatureLength - 1])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => publicOnly.Sign(message, signature)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.SignPreHash(hash, signature)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.ExportPrivateKey(new byte[Ed448.PrivateKeyLength])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.Pkcs8PrivateKeyLength).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => key.Sign(SignatureAlgorithm.Ed25519, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(signature).All(static value => value is DestinationSentinel);
			await Assert.That(key.Sign(message, signature, new byte[255])).IsEqualTo(Ed448.SignatureLength);
			await Assert.That(key.Verify(message, signature.AsSpan(0, Ed448.SignatureLength), new byte[255])).IsTrue();
		}
	}

	[Test]
	public async Task SignaturesOfTheWrongLengthFail()
	{
		using Ed448 key = Ed448.GenerateKey();
		byte[] message = CreateDeterministicSource(10);
		byte[] hash = Ed448Reference.Input(Ed448Variant.PreHash, message);
		byte[] signature = Sign(key, Ed448Variant.Pure, message, []);
		byte[] preHashSignature = Sign(key, Ed448Variant.PreHash, message, []);
		List<string> accepted = [];

		foreach (int delta in (int[])[-114, -57, -1, 1, 57])
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
		using Ed448 key = Ed448.GenerateKey();
		byte[] message = CreateDeterministicSource(200);
		byte[] hash = Ed448Reference.Input(Ed448Variant.PreHash, message);
		byte[] context = "context"u8.ToArray();
		List<string> failures = [];

		foreach (int offset in (int[])[0, 1, 63, 113, 114])
		{
			byte[] buffer = new byte[offset + message.Length + Ed448.SignatureLength];
			message.CopyTo(buffer, offset);
			key.Sign(buffer.AsSpan(offset, message.Length), buffer.AsSpan(0, Ed448.SignatureLength), context);

			if (!key.Verify(message, buffer.AsSpan(0, Ed448.SignatureLength), context))
			{
				failures.Add($"message at {offset}");
			}

			hash.CopyTo(buffer, offset);
			key.SignPreHash(buffer.AsSpan(offset, hash.Length), buffer.AsSpan(0, Ed448.SignatureLength), context);

			if (!key.VerifyPreHash(hash, buffer.AsSpan(0, Ed448.SignatureLength), context))
			{
				failures.Add($"hash at {offset}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The first verification goes without the table of the public key, later ones use it.
	[Test]
	public async Task FirstAndLaterVerificationsAgree()
	{
		Random random = new(5);
		byte[] seed = new byte[Ed448.PrivateKeyLength];
		random.NextBytes(seed);
		(byte[] mixedPublicKey, byte[] mixedMessage, byte[] mixedSignature) = SignWithTorsionNonce(random);
		(byte[] torsionMessage, byte[] torsionSignature) = SignForTorsionKey(random, OrderFour);
		List<(byte[] PublicKey, byte[] Message, byte[] Signature)> cases = [(mixedPublicKey, mixedMessage, mixedSignature), (Encode(OrderFour), torsionMessage, torsionSignature)];
		byte[] publicKey = Ed448Reference.PublicKey(seed);

		for (int i = 0; i < 4; ++i)
		{
			byte[] message = new byte[i * 37];
			random.NextBytes(message);
			cases.Add((publicKey, message, Ed448Reference.Sign(seed, message, EmptyContextDomain)));
			cases.Add((mixedPublicKey, message, Ed448Reference.Sign(seed, message, EmptyContextDomain)));
		}

		foreach (BigInteger s in (BigInteger[])[0, 1, L - 1])
		{
			cases.Add((publicKey, mixedMessage, Ed448Reference.Signature(Encode(Multiply(Base, RandomBelow(random, L))), s)));
		}

		// Each case also with the next message, which the signature does not fit.
		int count = cases.Count;

		for (int i = 0; i < count; ++i)
		{
			cases.Add(cases[i] with { Message = cases[(i + 1) % count].Message });
		}

		bool[] expected = [.. cases.Select(static c => Ed448Reference.Verify(c.PublicKey, c.Message, c.Signature, EmptyContextDomain))];
		Dictionary<string, Ed448> later = [];
		List<string> failures = [];

		try
		{
			foreach (byte[] key in cases.Select(static c => c.PublicKey).Distinct(new ByteArrayComparer()))
			{
				Ed448 instance = Ed448.ImportPublicKey(key);
				later[Convert.ToHexString(key)] = instance;
				_ = instance.Verify([], new byte[Ed448.SignatureLength]) | instance.Verify([], new byte[Ed448.SignatureLength]);
			}

			for (int i = 0; i < cases.Count; ++i)
			{
				(byte[] key, byte[] message, byte[] signature) = cases[i];
				using Ed448 first = Ed448.ImportPublicKey(key);

				if (first.Verify(message, signature) != expected[i] || later[Convert.ToHexString(key)].Verify(message, signature) != expected[i])
				{
					failures.Add($"case {i}, expected {expected[i]}");
				}
			}
		}
		finally
		{
			foreach (Ed448 instance in later.Values)
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

	// Each thread may build the table of the public key.
	[Test]
	public async Task ConcurrentVerificationsWithANewInstanceAgree()
	{
		const int threadCount = 8;
		using Ed448 signer = Ed448.GenerateKey();
		byte[] publicKey = ExportPublicKey(signer);
		byte[] message = CreateDeterministicSource(30);
		byte[] other = CreateDeterministicSource(31);
		byte[] signature = Sign(signer, SignatureAlgorithm.Ed448, message);
		int failures = 0;

		for (int round = 0; round < 4; ++round)
		{
			using Ed448 key = Ed448.ImportPublicKey(publicKey);
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
		using Ed448 key = Ed448.GenerateKey();
		byte[][] messages = [.. Enumerable.Range(0, threadCount).Select(CreateDeterministicSource)];
		byte[][] expected = [.. messages.Select(message => Sign(key, SignatureAlgorithm.Ed448, message))];
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
					byte[] signature = Sign(key, SignatureAlgorithm.Ed448, messages[index]);

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
	public async Task ExternalKeysAndSignaturesMatch()
	{
		byte[] subjectPublicKeyInfo = Convert.FromBase64String(ExternalPublicKey);
		byte[] privateKey = Convert.FromBase64String(ExternalPrivateKey);
		byte[] seed = Convert.FromHexString("50AF05BB3AB1747FAD80F2E793C4D0ED6E2BC6AD52EB9D3E938CAE5896CFFABE4239F436AECBB46A9E70B25D8BB6B4F15AC83AAEC27203C68D");
		byte[] publicKey = Convert.FromHexString("E0C22C28E767E731B7C3BE14463D2DF6AA4B50168E83F9671F329724583138A6825D0989D7C8BCC3E877063761FFF881CDFA8E753AC9BE5F80");
		using Ed448 fromPublicKey = Ed448.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using Ed448 fromPrivateKey = Ed448.ImportPkcs8PrivateKey(privateKey);
		using Ed448 fromPrivateKeyWithPublicKey = Ed448.ImportPkcs8PrivateKey(Pkcs8(1, CurvePrivateKey(seed), PublicKeyField(publicKey)));
		using ISignatureKey fromPublicPem = SignatureKey.ImportFromPem($"-----BEGIN PUBLIC KEY-----\n{ExternalPublicKey}\n-----END PUBLIC KEY-----\n");
		using ISignatureKey fromPrivatePem = SignatureKey.ImportFromPem($"-----BEGIN PRIVATE KEY-----\n{ExternalPrivateKey}\n-----END PRIVATE KEY-----\n");
		byte[] message = "message"u8.ToArray();
		byte[] signature = Convert.FromHexString(ExternalSignature);
		byte[] contextSignature = Convert.FromHexString(ExternalContextSignature);
		byte[] preHashSignature = Convert.FromHexString(ExternalPreHashSignature);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(fromPublicKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(fromPublicKey)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);

			foreach (Ed448 key in (Ed448[])[fromPrivateKey, fromPrivateKeyWithPublicKey])
			{
				await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(seed, CollectionOrdering.Matching);
				await Assert.That(ExportPublicKey(key)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			}

			await Assert.That(Sign(fromPrivateKey, SignatureAlgorithm.Ed448, message)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(Sign(fromPrivateKey, Ed448Variant.Pure, message, "context"u8.ToArray())).IsEquivalentTo(contextSignature, CollectionOrdering.Matching);
			await Assert.That(Sign(fromPrivateKey, Ed448Variant.PreHash, message, [])).IsEquivalentTo(preHashSignature, CollectionOrdering.Matching);
			await Assert.That(fromPublicKey.Verify(message, contextSignature, "context"u8)).IsTrue();
			await Assert.That(Verify(fromPublicKey, Ed448Variant.PreHash, message, preHashSignature, [])).IsTrue();
			await Assert.That(fromPublicPem).IsTypeOf<Ed448>();
			await Assert.That(fromPrivatePem).IsTypeOf<Ed448>();
			await Assert.That(fromPublicPem.Verify(SignatureAlgorithm.Ed448, message, signature)).IsTrue();
			await Assert.That(Sign(fromPrivatePem, SignatureAlgorithm.Ed448, message)).IsEquivalentTo(signature, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task Pkcs8ImportAcceptsOptionalPartsThatMatch()
	{
		using Ed448 key = Ed448.GenerateKey();
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
				using Ed448 imported = Ed448.ImportPkcs8PrivateKey(encoding);
				await Assert.That(ExportPkcs8PrivateKey(imported)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(Convert.ToHexString(encoding));
			}
		}
	}

	[Test]
	public async Task Pkcs8ImportRejectsInvalidKeys()
	{
		using Ed448 key = Ed448.GenerateKey();
		using Ed448 other = Ed448.GenerateKey();
		byte[] seed = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(key);
		byte[] curvePrivateKey = CurvePrivateKey(seed);
		byte[] der = Pkcs8(0, curvePrivateKey);
		byte[][] invalid =
		[
			// A public key that does not match, of the wrong length, with unused bits, or not in a primitive [1].
			Pkcs8(1, curvePrivateKey, PublicKeyField(ExportPublicKey(other))), Pkcs8(1, curvePrivateKey, PublicKeyField(publicKey.AsSpan(1).ToArray())), Pkcs8(1, curvePrivateKey, PublicKeyField([.. publicKey, 0])),
			Pkcs8(1, curvePrivateKey, Tlv(0x81, [1, .. publicKey])), Pkcs8(1, curvePrivateKey, Tlv(0xA1, Tlv(0x03, [0, .. publicKey]))), Pkcs8(0, curvePrivateKey, PublicKeyField(publicKey)),
			// A seed of the wrong length, not in a CurvePrivateKey, or not in DER.
			Pkcs8(0, CurvePrivateKey(seed.AsSpan(1).ToArray())), Pkcs8(0, CurvePrivateKey([.. seed, 0])), Pkcs8(0, seed), Pkcs8(0, [0x03, 0x39, .. seed]), Pkcs8(0, [0x04, 0x81, 0x39, .. seed]),
			Pkcs8(0, [.. curvePrivateKey, 0x05, 0x00]), Pkcs8(0, []),
			// Another version or algorithm: Ed448 with parameters, X448 and Ed25519.
			Pkcs8(2, curvePrivateKey), Sequence([0x02, 0x01, 0x00], Sequence(Oid(Ed448Oid), [0x05, 0x00]), Tlv(0x04, curvePrivateKey)), Sequence([0x02, 0x01, 0x00], Sequence(Oid("1.3.101.111")), Tlv(0x04, curvePrivateKey)),
			Sequence([0x02, 0x01, 0x00], Sequence(Oid("1.3.101.112")), Tlv(0x04, curvePrivateKey)),
			// The key in BER, with an indefinite length.
			[0x30, 0x80, .. der.AsSpan(2), 0x00, 0x00]
		];

		using (Assert.Multiple())
		{
			for (int i = 0; i < invalid.Length; ++i)
			{
				byte[] encoding = invalid[i];
				await Assert.That(() => Ed448.ImportPkcs8PrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because($"case {i}");
			}
		}
	}

	[Test]
	public async Task FailedPkcs8ImportErasesTheKey()
	{
		using Ed448 key = Ed448.GenerateKey();
		using Ed448 other = Ed448.GenerateKey();
		byte[] encoding = Pkcs8(1, CurvePrivateKey(ExportPrivateKey(key)), PublicKeyField(ExportPublicKey(other)));
		Ed448Key core = default;

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

	[Test]
	public async Task ClearErasesTheKey()
	{
		byte[] message = CreateDeterministicSource(10);
		Ed448Key core = default;
		core.GenerateKey();
		byte[] signature = new byte[Ed448.SignatureLength];
		core.Sign(message, [], signature);
		bool verified = core.Verify(message, signature, []) & core.Verify(message, signature, []);
		core.Clear();

		using (Assert.Multiple())
		{
			await Assert.That(verified).IsTrue();
			await Assert.That(IsErased(ref core)).IsTrue();
		}
	}

	// Otherwise the new key would verify with the table of the old one.
	[Test]
	public async Task ReplacingTheKeyDropsTheTable()
	{
		using Ed448 first = Ed448.GenerateKey();
		using Ed448 second = Ed448.GenerateKey();
		byte[] message = CreateDeterministicSource(20);
		byte[] firstPublicKey = ExportPublicKey(first);
		byte[] firstSignature = Sign(first, SignatureAlgorithm.Ed448, message);
		byte[] secondSignature = Sign(second, SignatureAlgorithm.Ed448, message);
		byte[] secondPublicKey = ExportPublicKey(second);
		byte[] secondPrivateKey = ExportPrivateKey(second);
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(second);
		byte[] pkcs8 = ExportPkcs8PrivateKey(second);
		List<string> failures = [];

		for (int i = 0; i < 5; ++i)
		{
			Ed448Key core = default;
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
		Ed448 key = Ed448.GenerateKey();
		byte[] message = CreateDeterministicSource(10);
		byte[] hash = Ed448Reference.Input(Ed448Variant.PreHash, message);
		byte[] signature = Sign(key, SignatureAlgorithm.Ed448, message);
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.ExportPrivateKey(new byte[Ed448.PrivateKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPublicKey(new byte[Ed448.PublicKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Sign(message, new byte[Ed448.SignatureLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Verify(message, signature)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.SignPreHash(hash, new byte[Ed448.SignatureLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.VerifyPreHash(hash, signature)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task SigningAndVerificationDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan<ulong> allocates a field handle.
		SkipUnlessOptimized<Ed448>();

		using Ed448 key = Ed448.GenerateKey();
		using Ed448 verifier = Ed448.ImportPublicKey(ExportPublicKey(key));
		byte[] message = CreateDeterministicSource(100);
		byte[] hash = Ed448Reference.Input(Ed448Variant.PreHash, message);
		byte[] context = "context"u8.ToArray();
		byte[] signature = new byte[Ed448.SignatureLength];

		// The table of key is built before the count; verifier verifies without one.
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

		static bool Exercise(Ed448 key, byte[] message, byte[] hash, byte[] context, byte[] signature)
		{
			key.Sign(SignatureAlgorithm.Ed448, message, signature);
			bool valid = key.Verify(SignatureAlgorithm.Ed448, message, signature);
			key.Sign(message, signature, context);
			valid &= key.Verify(message, signature, context);
			key.SignPreHash(hash, signature, context);
			return valid & key.VerifyPreHash(hash, signature, context);
		}
	}

	// [S]B − [k]A = R holds when [k]A = [j]A, which the search finds by trying j.
	private static (byte[] Message, byte[] Signature) SignForTorsionKey(Random random, EdwardsValue point)
	{
		byte[] publicKey = Encode(point);
		BigInteger s = RandomBelow(random, L);
		EdwardsValue sB = Multiply(Base, s);

		for (int counter = 0; ; ++counter)
		{
			byte[] message = BitConverter.GetBytes(counter);

			for (int j = 0; j < 4; ++j)
			{
				byte[] encodedR = Encode(Add(sB, Negate(Multiply(point, j))));
				BigInteger k = Ed448Reference.HashToScalar(EmptyContextDomain, [.. encodedR, .. publicKey], message);

				if (Multiply(point, k % 4) == Multiply(point, j))
				{
					return (message, Ed448Reference.Signature(encodedR, s));
				}
			}
		}
	}

	// R = −[j]T and S = k·a give [S]B − [k]A = −[k]T, so k ≡ j (mod 4) is needed.
	private static (byte[] PublicKey, byte[] Message, byte[] Signature) SignWithTorsionNonce(Random random)
	{
		BigInteger a = RandomBelow(random, L);
		byte[] publicKey = Encode(Add(Multiply(Base, a), OrderFour));

		for (int counter = 0; ; ++counter)
		{
			byte[] message = BitConverter.GetBytes(counter);

			for (int j = 1; j < 4; ++j)
			{
				byte[] encodedR = Encode(Negate(Multiply(OrderFour, j)));
				BigInteger k = Ed448Reference.HashToScalar(EmptyContextDomain, [.. encodedR, .. publicKey], message);

				if (k % 4 == j)
				{
					return (publicKey, message, Ed448Reference.Signature(encodedR, k * a % L));
				}
			}
		}
	}

	private static byte[] WithSignBit(byte[] encoding)
	{
		return WithLastByte(encoding, 0x80);
	}

	private static byte[] WithLastByte(byte[] encoding, byte bits)
	{
		byte[] copy = (byte[])encoding.Clone();
		copy[56] |= bits;
		return copy;
	}

	private static byte[] SubjectPublicKeyInfo(byte[] publicKey)
	{
		return Sequence(Sequence(Oid(Ed448Oid)), Tlv(0x03, [0, .. publicKey]));
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
		return Sequence([[0x02, 0x01, (byte)version], Sequence(Oid(Ed448Oid)), Tlv(0x04, privateKey), .. optional]);
	}

	private static bool IsErased(ref Ed448Key key)
	{
		return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<Ed448Key, byte>(ref key), Unsafe.SizeOf<Ed448Key>()).IndexOfAnyExcept((byte)0) < 0;
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
