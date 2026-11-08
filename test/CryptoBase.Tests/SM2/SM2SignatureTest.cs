using CryptoBase.EllipticCurves;
using CryptoBase.SM2;
using CryptoBase.Tests.EllipticCurves;
using CryptoBase.Tests.Signatures.Ecdsa;
using System.Numerics;
using static CryptoBase.Tests.SM2.SM2TestUtils;

namespace CryptoBase.Tests.SM2;

// Assert.That runs its delegates at the await, and Parallel.For before it returns, so the delegates read the keys before they are disposed.
// ReSharper disable AccessToDisposedClosure
public class SM2SignatureTest
{
	private const string CurveOid = "1.2.156.10197.1.301";

	private static readonly byte[][] Ids = [[], "1234567812345678"u8.ToArray(), "ALICE123@YAHOO.COM"u8.ToArray(), [0x00], [.. Enumerable.Range(0, 8191).Select(static i => (byte)i)]];

	// The reference verifies what the key signs, for IDs from empty to the longest and messages around the SM3 block, whose padding takes a block of its own from 56 bytes on.
	[Test]
	public async Task SignaturesVerifyWithTheReference()
	{
		using SM2Key key = SM2Key.GenerateKey();
		CurvePoint publicKey = Curve.DecodePoint(ExportPublicKey(key));
		List<string> failures = [];

		foreach (byte[] id in Ids)
		{
			foreach (int length in (int[])[0, 1, 23, 24, 55, 56, 64, 1000])
			{
				byte[] message = [.. Enumerable.Range(0, length).Select(static i => (byte)(i * 7))];
				byte[] signature = Sign(key, message, id);
				(BigInteger r, BigInteger s) = ReadSignature(signature);

				if (!ReferenceVerify(publicKey, id, message, r, s) || !key.Verify(message, signature, id))
				{
					failures.Add($"ID of {id.Length} bytes, message of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The reference signs with nonces of its own; the key verifies those signatures and nothing near them.
	[Test]
	public async Task ReferenceSignaturesVerify()
	{
		Random random = new(1);
		List<string> failures = [];

		foreach (BigInteger d in (BigInteger[])[1, 2, N - 3, N - 2, ECReference.RandomBelow(random, N - 2) + 1])
		{
			using SM2Key key = SM2Key.ImportPrivateKey(Encode(d));
			CurvePoint publicKey = Reference.PublicKey(d);

			foreach (byte[] id in Ids.Take(3))
			{
				byte[] message = [.. Enumerable.Range(0, random.Next(100)).Select(_ => (byte)random.Next(256))];
				BigInteger e = ModulusCase.Decode(Sm3(ReferenceZ(id, publicKey), message));
				BigInteger k = ECReference.RandomBelow(random, N - 1) + 1;
				BigInteger r = (e + Reference.PublicKey(k).X) % N;
				BigInteger s = ECReference.Inverse((1 + d) % N, N) * ((k - r * d) % N + N) % N;

				if (!key.Verify(message, DerSignature(r, s), id) || key.Verify(message, DerSignature(r, (s + 1) % N), id) || key.Verify(message, DerSignature((r + 1) % N, s), id))
				{
					failures.Add($"d = {d:X}, ID of {id.Length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// GB/T 32918.2-2016, Sec. 7.1, B1 and B2 reject r and s outside [1, n − 1], and B5 a t of 0, before any product.
	[Test]
	public async Task SignatureValuesOutsideTheRangeFail()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] message = "message"u8.ToArray();
		(BigInteger r, BigInteger s) = ReadSignature(Sign(key, message));
		(BigInteger R, BigInteger S)[] invalid = [(0, s), (r, 0), (N, s), (r, N), (r + N, s), (r, s + N), (-r, s), (r, -s), (r, N - r), ((r + s) % N, N - (r + s) % N)];

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(message, DerSignature(r, s))).IsTrue();

			foreach ((BigInteger R, BigInteger S) values in invalid)
			{
				await Assert.That(key.Verify(message, DerSignature(values.R, values.S))).IsFalse().Because($"r = {values.R:X}, s = {values.S:X}");
			}
		}
	}

	[Test]
	public async Task OtherIdsKeysAndMessagesFail()
	{
		using SM2Key key = SM2Key.GenerateKey();
		using SM2Key other = SM2Key.GenerateKey();
		byte[] message = "message"u8.ToArray();
		byte[] id = "ALICE123@YAHOO.COM"u8.ToArray();
		byte[] signature = Sign(key, message, id);

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(message, signature, id)).IsTrue();
			await Assert.That(key.Verify(message, signature)).IsFalse();
			await Assert.That(key.Verify(message, signature, [])).IsFalse();
			await Assert.That(key.Verify(message, signature, "ALICE123@YAHOO.CON"u8)).IsFalse();
			await Assert.That(key.Verify(message, signature, [.. id, 0])).IsFalse();
			await Assert.That(other.Verify(message, signature, id)).IsFalse();
			await Assert.That(key.Verify("messagE"u8, signature, id)).IsFalse();
			await Assert.That(key.Verify([.. message, 0], signature, id)).IsFalse();
		}
	}

	// ENTL holds the bit length of an ID in 16 bits, so 8191 bytes is the most.
	[Test]
	public async Task IdsOfMoreThan8191BytesThrow()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] id = new byte[SM2Key.MaxIdLength + 1];
		byte[] signature = new byte[SM2Key.MaxSignatureLength];

		using (Assert.Multiple())
		{
			await Assert.That(SM2Key.MaxIdLength).IsEqualTo(8191);
			await Assert.That(() => key.Sign([1], signature, id)).Throws<ArgumentException>().WithParameterName("id");
			await Assert.That(() => key.Verify([1], signature, id)).Throws<ArgumentException>().WithParameterName("id");
		}
	}

	// d lies in [1, n − 2]: 1 + d has no inverse for n − 1. The PKCS #8 keys hold no public key, which would not match.
	[Test]
	public async Task PrivateKeysOutsideTheRangeThrow()
	{
		List<string> failures = [];

		foreach (BigInteger value in (BigInteger[])[0, N - 1, N, N + 1, (BigInteger.One << 256) - 1])
		{
			byte[] encoded = Encode(value);
			byte[] pkcs8 = EcdsaTestUtils.Pkcs8(CurveOid, EcdsaTestUtils.ECPrivateKey(1, encoded, CurveOid, null));

			if (!Throws(() => SM2Key.ImportPrivateKey(encoded)) || !Throws(() => SM2Key.ImportPkcs8PrivateKey(pkcs8)))
			{
				failures.Add($"{value:X}");
			}
		}

		foreach (BigInteger value in (BigInteger[])[1, N - 2])
		{
			using SM2Key key = SM2Key.ImportPrivateKey(Encode(value));
			using SM2Key fromPkcs8 = SM2Key.ImportPkcs8PrivateKey(EcdsaTestUtils.Pkcs8(CurveOid, EcdsaTestUtils.ECPrivateKey(1, Encode(value), CurveOid, null)));

			if (!key.Verify("message"u8, Sign(key, "message"u8.ToArray())) || Curve.DecodePoint(ExportPublicKey(key)) != Reference.PublicKey(value) || !ExportPublicKey(fromPkcs8).AsSpan().SequenceEqual(ExportPublicKey(key)))
			{
				failures.Add($"{value:X} signs or exports wrongly");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A candidate of n − 1, outside [1, n − 2], is drawn again, as are 0 and the values from n on, which ECKey rejects.
	[Test]
	public async Task GenerateKeyDrawsAgainOutsideTheRange()
	{
		BigInteger expected = N - 2;
		using SM2Key key = SM2Key.GenerateKey(Fill(Encode(N - 1), Encode(0), Encode(N), Encode(expected)));
		byte[] d = new byte[SM2Key.PrivateKeyLength];
		key.ExportPrivateKey(d);

		await Assert.That(ModulusCase.Decode(d)).IsEqualTo(expected);
	}

	// A6 of GB/T 32918.2-2016, Sec. 6.1, takes another nonce if r = 0, r + k = n or s = 0; an e that the reference picks for each makes it so.
	[Test]
	public async Task TrySignRejectsTheNoncesThatTheStandardRejects()
	{
		BigInteger d = Integer("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8");
		BigInteger k = Integer("59276E27 D506861A 16680F3A D9C02DCC EF3CC1FA 3CDBE4CE 6D54B80D EAC1BC21");
		using SM2Key key = SM2Key.ImportPrivateKey(Encode(d));
		BigInteger x = Reference.PublicKey(k).X % N;
		(string Case, BigInteger E)[] cases = [("r = 0", (N - x) % N), ("r + k = n", ((N - k - x) % N + N) % N), ("s = 0", (k * ECReference.Inverse(d, N) - x + N) % N)];
		List<string> failures = [];

		foreach ((string @case, BigInteger e) in cases)
		{
			if (key.GetState().TrySign(Scalar(e), Scalar(k), out _, out _))
			{
				failures.Add(@case);
			}
		}

		if (!key.GetState().TrySign(Scalar(1), Scalar(k), out FieldElement<SM2Order> r, out FieldElement<SM2Order> s) || !ReferenceVerifyHash(d, 1, Value(in r), Value(in s)))
		{
			failures.Add("e = 1");
		}

		await Assert.That(failures).IsEmpty();
	}

	// With an empty additional input the nonce follows from d and e alone; other inputs change it.
	[Test]
	public async Task SigningIsDeterministicWithoutAdditionalData()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] message = "message"u8.ToArray();
		byte[] first = SignWith(key, message, []);

		using (Assert.Multiple())
		{
			await Assert.That(SignWith(key, message, [])).IsEquivalentTo(first, CollectionOrdering.Matching);
			await Assert.That(SignWith(key, message, [1])).IsNotEquivalentTo(first);
			await Assert.That(Sign(key, message)).IsNotEquivalentTo(first);
			await Assert.That(key.Verify(message, first)).IsTrue();
		}
	}

	// Import, decryption and the key exchange leave (1 + d)⁻¹ alone; the first signature computes it, plain (1 + d)⁻¹·R mod n, and keeps it, and disposal erases it. A signature that comes while another computes it computes its own, which neither stays in the state nor changes the stage.
	[Test]
	public async Task TheFirstSignatureComputesTheInverse()
	{
		int missing = InverseStage("InverseMissing");
		int computing = InverseStage("InverseComputing");
		int ready = InverseStage("InverseReady");
		Random random = new(32918);
		BigInteger d = ECReference.RandomBelow(random, N - 2) + 1;
		BigInteger expected = ECReference.Inverse((1 + d) % N, N) * ((BigInteger.One << 256) % N) % N;
		SM2Key key = SM2Key.ImportPrivateKey(Encode(d));
		using SM2Key peer = SM2Key.GenerateKey();
		byte[] message = "message"u8.ToArray();
		byte[] plaintext = [1, 2, 3];
		(int Stage, BigInteger Inverse) imported = InverseOf(key);
		bool decrypted = Decrypt(key, Encrypt(key, plaintext)) is { } result && result.AsSpan().SequenceEqual(plaintext);
		bool exchanged = ExchangeKeys(key, peer);
		(int Stage, BigInteger Inverse) unused = InverseOf(key);
		SetInverseStage(key, computing);
		byte[] concurrent = Sign(key, message);
		(int Stage, BigInteger Inverse) meanwhile = InverseOf(key);
		SetInverseStage(key, missing);
		byte[] first = Sign(key, message);
		(int Stage, BigInteger Inverse) signed = InverseOf(key);
		byte[] second = Sign(key, message);
		bool verified = key.Verify(message, concurrent) && key.Verify(message, first) && key.Verify(message, second);
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(imported).IsEqualTo((missing, BigInteger.Zero));
			await Assert.That(decrypted && exchanged).IsTrue();
			await Assert.That(unused).IsEqualTo((missing, BigInteger.Zero));
			await Assert.That(meanwhile).IsEqualTo((computing, BigInteger.Zero));
			await Assert.That(signed).IsEqualTo((ready, expected));
			await Assert.That(verified).IsTrue();
			await Assert.That(InverseOf(key)).IsEqualTo((missing, BigInteger.Zero));
		}
	}

	// Threads that sign at once on a key that has not signed yet race to compute (1 + d)⁻¹; every signature verifies, and the key keeps the whole value.
	[Test]
	public async Task ConcurrentFirstSignaturesAgree()
	{
		const int threads = 8;
		byte[] message = "message"u8.ToArray();
		List<string> failures = [];

		for (int round = 0; round < 16; ++round)
		{
			using SM2Key key = SM2Key.GenerateKey();
			byte[] privateKey = new byte[SM2Key.PrivateKeyLength];
			key.ExportPrivateKey(privateKey);
			BigInteger d = ModulusCase.Decode(privateKey);
			byte[][] signatures = new byte[threads][];
			using Barrier barrier = new(threads);
			Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads }, i =>
			{
				barrier.SignalAndWait();
				signatures[i] = Sign(key, message);
			});

			if (!signatures.All(signature => key.Verify(message, signature)) || InverseOf(key) != (InverseStage("InverseReady"), ECReference.Inverse((1 + d) % N, N) * ((BigInteger.One << 256) % N) % N))
			{
				failures.Add($"round {round}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The first verification goes without a table, the next ones with the table of EcdsaKey and the later ones with the windows of the key, on several threads at once.
	[Test]
	public async Task OneInstanceSignsAndVerifiesConcurrently()
	{
		using SM2Key signer = SM2Key.GenerateKey();
		byte[] publicKey = ExportPublicKey(signer);
		byte[][] messages = [.. Enumerable.Range(0, 64).Select(static i => BitConverter.GetBytes(i))];
		byte[][] signatures = new byte[messages.Length][];

		for (int round = 0; round < 4; ++round)
		{
			using SM2Key verifier = SM2Key.ImportPublicKey(publicKey);
			bool[] valid = new bool[messages.Length];
			Parallel.For(0, messages.Length, i =>
			{
				signatures[i] = Sign(signer, messages[i]);
				valid[i] = verifier.Verify(messages[i], signatures[i]) && !verifier.Verify(messages[(i + 1) % messages.Length], signatures[i]);
			});

			await Assert.That(valid).All(static value => value);
		}
	}

	// A key counts its verifications and builds the windows of its public key for verification at the threshold, and not those of encryption, which the encryption after them builds by its own count; before and after it, the key decides each signature, valid or with s off by one, as the reference does.
	[Test]
	public async Task VerificationsBeforeAndAfterTheWindowsMatchTheReference()
	{
		int threshold = TableThreshold("VerificationTableThreshold");
		Random random = new(6);
		BigInteger d = ECReference.RandomBelow(random, N - 2) + 1;
		CurvePoint publicKey = Reference.PublicKey(d);
		using SM2Key key = SM2Key.ImportPublicKey(EncodePoint(publicKey));
		List<string> failures = [];

		for (int i = 1; i <= 2 * threshold; ++i)
		{
			byte[] message = new byte[i];
			random.NextBytes(message);
			BigInteger e = ModulusCase.Decode(Sm3(ReferenceZ(SM2Key.DefaultId, publicKey), message));
			BigInteger k = ECReference.RandomBelow(random, N - 1) + 1;
			BigInteger r = (e + Reference.PublicKey(k).X) % N;
			BigInteger s = (ECReference.Inverse((1 + d) % N, N) * ((k - r * d) % N + N) + i % 2) % N;
			bool expected = ReferenceVerify(publicKey, SM2Key.DefaultId, message, r, s);

			if (key.Verify(message, DerSignature(r, s)) != expected || expected != i % 2 is 0)
			{
				failures.Add($"verification {i}: the result differs from the reference");
			}

			if (HasVerificationTable(key) != i >= threshold || HasTable(key))
			{
				failures.Add($"verification {i}: the windows are {(HasVerificationTable(key) ? "built" : "missing")} and those of encryption {(HasTable(key) ? "built" : "missing")}");
			}
		}

		byte[] plaintext = [1, 2, 3];
		BigInteger ephemeral = ECReference.RandomBelow(random, N - 1) + 1;
		byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(plaintext.Length)];
		_ = key.Encrypt(plaintext, ciphertext, Fill(Encode(ephemeral)));

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(ciphertext).IsEquivalentTo(ReferenceEncrypt(publicKey, plaintext, ephemeral), CollectionOrdering.Matching);
		}
	}

	// A key exchange with key as the initiator and peer as the responder, with confirmation.
	private static bool ExchangeKeys(SM2Key key, SM2Key peer)
	{
		Span<byte> ephemeralA = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> ephemeralB = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> keyA = stackalloc byte[16];
		Span<byte> keyB = stackalloc byte[16];
		Span<byte> confirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		Span<byte> peerConfirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		using SM2KeyExchange initiator = SM2KeyExchange.Create(key, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(peer, SM2Key.DefaultId, SM2KeyExchangeRole.Responder);
		initiator.ExportEphemeralPublicKey(ephemeralA);
		responder.ExportEphemeralPublicKey(ephemeralB);
		return responder.TryDeriveKey(key, SM2Key.DefaultId, ephemeralA, keyB, confirmation, peerConfirmation) && initiator.TryDeriveKey(peer, SM2Key.DefaultId, ephemeralB, keyA, confirmation, peerConfirmation) && keyA.SequenceEqual(keyB);
	}

	private static bool ReferenceVerifyHash(BigInteger d, BigInteger e, BigInteger r, BigInteger s)
	{
		CurvePoint? point = Reference.Add(Reference.Multiply(Reference.Generator, s), Reference.Multiply(Reference.PublicKey(d), (r + s) % N));
		return point is not null && (e + point.X) % N == r;
	}

	private static byte[] SignWith(SM2Key key, byte[] message, byte[] additionalData)
	{
		byte[] signature = new byte[SM2Key.MaxSignatureLength];
		int written = key.GetState().Sign(message, SM2Key.DefaultId, additionalData, signature);
		return signature.AsSpan(0, written).ToArray();
	}

	private static (BigInteger R, BigInteger S) ReadSignature(byte[] signature)
	{
		return EcdsaTestUtils.ReadDerSignature(signature);
	}

	private static byte[] ExportPublicKey(SM2Key key)
	{
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	private static bool Throws(Func<SM2Key> import)
	{
		try
		{
			using SM2Key _ = import();
			return false;
		}
		catch (ArgumentException e) when (e.ParamName is "source")
		{
			return true;
		}
	}
}
