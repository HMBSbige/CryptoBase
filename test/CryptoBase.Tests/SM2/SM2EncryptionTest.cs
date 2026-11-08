using CryptoBase.SM2;
using CryptoBase.Tests.EllipticCurves;
using CryptoBase.Tests.Signatures.Ecdsa;
using System.Formats.Asn1;
using System.Numerics;
using static CryptoBase.Tests.SM2.SM2TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SM2;

// Assert.That runs its delegates at the await, and Parallel.For before it returns, so the delegates read the keys before they are disposed.
// ReSharper disable AccessToDisposedClosure
public class SM2EncryptionTest
{
	// Around the 32-byte blocks of the key stream and the 64-byte blocks of SM3, and the groups of vector lanes and the 4096-byte chunks that take the key stream, from block 1 in decryption and from block 2 in encryption.
	private static readonly int[] Lengths = [1, 2, 23, 31, 32, 33, 55, 56, 63, 64, 65, 96, 97, 129, 288, 545, 1000, 1056, 4095, 4096, 4097, 4127, 4128, 4129, 8225];

	private static readonly BigInteger PrivateKey = Integer("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8");

	// From a fixed k, both formats hold the ciphertext of the reference, and the reference decrypts what the key writes from fresh randomness.
	[Test]
	public async Task CiphertextsMatchTheReference()
	{
		using SM2Key key = SM2Key.ImportPrivateKey(Encode(PrivateKey));
		CurvePoint publicKey = Reference.PublicKey(PrivateKey);
		Random random = new(1);
		List<string> failures = [];

		foreach (int length in Lengths)
		{
			byte[] plaintext = new byte[length];
			random.NextBytes(plaintext);
			BigInteger k = ECReference.RandomBelow(random, N - 1) + 1;
			byte[] expected = ReferenceEncrypt(publicKey, plaintext, k);
			byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(length)];
			_ = key.Encrypt(plaintext, ciphertext, Fill(Encode(k)));
			byte[] der = new byte[SM2Key.GetMaxDerCiphertextLength(length)];
			int derLength = key.EncryptDer(plaintext, der, Fill(Encode(k)));
			CurvePoint c1 = Curve.DecodePoint(expected.AsSpan(0, 65));
			byte[] expectedDer = DerCiphertext(c1.X, c1.Y, expected.AsSpan(65, 32).ToArray(), expected.AsSpan(97).ToArray());

			if (!ciphertext.AsSpan().SequenceEqual(expected) || !der.AsSpan(0, derLength).SequenceEqual(expectedDer))
			{
				failures.Add($"{length} bytes: the ciphertext differs from the reference");
			}

			if (ReferenceDecrypt(PrivateKey, Encrypt(key, plaintext)) is not { } decrypted || !decrypted.AsSpan().SequenceEqual(plaintext))
			{
				failures.Add($"{length} bytes: the reference does not decrypt the ciphertext");
			}

			if (Decrypt(key, expected) is not { } plain || !plain.AsSpan().SequenceEqual(plaintext) || DecryptDer(key, expectedDer) is not { } plainDer || !plainDer.AsSpan().SequenceEqual(plaintext))
			{
				failures.Add($"{length} bytes: the key does not decrypt the ciphertext of the reference");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A public key encrypts; only the private key decrypts, and other keys fail.
	[Test]
	public async Task OnlyThePrivateKeyDecrypts()
	{
		using SM2Key key = SM2Key.GenerateKey();
		using SM2Key other = SM2Key.GenerateKey();
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		using SM2Key encryptor = SM2Key.ImportPublicKey(publicKey);
		byte[] plaintext = "secret"u8.ToArray();
		byte[] ciphertext = Encrypt(encryptor, plaintext);
		byte[] der = EncryptDer(encryptor, plaintext);

		using (Assert.Multiple())
		{
			await Assert.That(Decrypt(key, ciphertext)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(DecryptDer(key, der)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(Decrypt(other, ciphertext)).IsNull();
			await Assert.That(DecryptDer(other, der)).IsNull();
			await Assert.That(() => encryptor.TryDecrypt(ciphertext, new byte[ciphertext.Length], out _)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => encryptor.TryDecryptDer(der, new byte[der.Length], out _)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(Encrypt(encryptor, plaintext)).IsNotEquivalentTo(ciphertext);
		}
	}

	// A flipped bit anywhere fails: in C1 it leaves the curve or gives another point, in C3 or C2 the hash. Decryption then writes nothing.
	[Test]
	public async Task TamperedCiphertextsFailAndWriteNothing()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] plaintext = new byte[40];
		Random random = new(2);
		random.NextBytes(plaintext);
		byte[] ciphertext = Encrypt(key, plaintext);
		byte[] der = EncryptDer(key, plaintext);
		List<string> failures = [];

		foreach ((byte[] valid, bool isDer) in ((byte[], bool)[])[(ciphertext, false), (der, true)])
		{
			for (int i = 0; i < valid.Length; ++i)
			{
				byte[] tampered = Flip(valid, i);
				byte[] destination = CreateGuardedBuffer(0, valid.Length);
				bool decrypted = isDer ? key.TryDecryptDer(tampered, destination, out int written) : key.TryDecrypt(tampered, destination, out written);

				if (decrypted || written is not 0 || destination.AsSpan().ContainsAnyExcept(DestinationSentinel))
				{
					failures.Add($"{(isDer ? "SM2Cipher" : "C1 ‖ C3 ‖ C2")}, byte {i}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// GB/T 32918.4-2016, Sec. 7.1, B1: C1 must be a point on the curve, here uncompressed; and a ciphertext needs a C2 of at least one byte.
	[Test]
	public async Task InvalidC1AndShortCiphertextsFail()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] ciphertext = Encrypt(key, "secret"u8.ToArray());
		CurvePoint c1 = Curve.DecodePoint(ciphertext.AsSpan(0, 65));
		byte[] tail = ciphertext.AsSpan(65).ToArray();
		BigInteger p = Reference.P;
		BigInteger most = (BigInteger.One << 256) - 1;
		byte[][] invalid =
		[
			[], [.. ciphertext.AsSpan(0, 97)], [.. ciphertext.AsSpan(0, 96)],
			[0x02, .. ciphertext.AsSpan(1)], [0x03, .. ciphertext.AsSpan(1)], [0x06, .. ciphertext.AsSpan(1)], [0x00, .. ciphertext.AsSpan(1)],
			[.. EncodePoint(c1 with { Y = p - c1.Y + 1 }), .. tail],
			[.. new byte[65], .. tail],
			[0x04, .. Encode(p), .. Encode(c1.Y), .. tail],
			[0x04, .. Encode(c1.X), .. Encode(p), .. tail],
			[0x04, .. Encode(most), .. Encode(c1.Y), .. tail],
			[0x04, .. Encode(c1.X), .. Encode(most), .. tail],
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			if (Decrypt(key, encoding) is not null)
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// DER only: minimal INTEGERs that are not negative, a HASH of 32 bytes, a CipherText of at least one byte and nothing after the SEQUENCE.
	[Test]
	public async Task SM2CiphersOtherThanDerFail()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] plaintext = "secret"u8.ToArray();
		byte[] der = EncryptDer(key, plaintext);
		AsnParts parts = AsnParts.Read(der);
		byte[] x = parts.X;
		byte[] y = parts.Y;
		BigInteger xValue = new(x, isBigEndian: true);
		byte[][] invalid =
		[
			[.. der, 0],
			der.AsSpan(0, der.Length - 1).ToArray(),
			[0x31, .. der.AsSpan(1)],
			Sequence(DerInteger(x, padding: 1), DerInteger(y), OctetString(parts.Hash), OctetString(parts.CipherText)),
			Sequence(DerInteger(x), DerInteger(y), OctetString(parts.Hash.AsSpan(1).ToArray()), OctetString(parts.CipherText)),
			Sequence(DerInteger(x), DerInteger(y), OctetString([.. parts.Hash, 0]), OctetString(parts.CipherText)),
			Sequence(DerInteger(x), DerInteger(y), OctetString(parts.Hash), OctetString([])),
			Sequence(DerInteger(x), DerInteger(y), OctetString(parts.Hash)),
			Sequence(DerInteger(x), DerInteger(y), OctetString(parts.Hash), OctetString(parts.CipherText), OctetString([])),
			Sequence(DerInteger(y), DerInteger(x), OctetString(parts.Hash), OctetString(parts.CipherText)),
			Sequence(Negative(x), DerInteger(y), OctetString(parts.Hash), OctetString(parts.CipherText)),
			Sequence(DerInteger([1, .. Encode(xValue)]), DerInteger(y), OctetString(parts.Hash), OctetString(parts.CipherText)),
			[0x30, 0x80, .. der.AsSpan(2), 0x00, 0x00],
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			if (DecryptDer(key, encoding) is not null)
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(DecryptDer(key, Sequence(DerInteger(x), DerInteger(y), OctetString(parts.Hash), OctetString(parts.CipherText)))).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(failures).IsEmpty();
		}
	}

	// Coordinates of fewer than 32 significant bytes give shorter INTEGERs, and a top bit set the 0 byte of their sign; the first k of each kind of C1 = k·G, from k = 1 on, has one of each.
	[Test]
	public async Task SM2CiphersTakeEveryLengthOfCoordinate()
	{
		using SM2Key key = SM2Key.ImportPrivateKey(Encode(PrivateKey));
		CurvePoint publicKey = Reference.PublicKey(PrivateKey);
		byte[] plaintext = "secret"u8.ToArray();
		Dictionary<(int, int), BigInteger> firsts = [];
		CurvePoint c1 = Reference.Generator;

		for (BigInteger k = 1; k <= 2000; ++k)
		{
			firsts.TryAdd((Shape(c1.X), Shape(c1.Y)), k);
			c1 = Reference.Add(c1, Reference.Generator)!;
		}

		List<string> failures = [];

		foreach (BigInteger k in firsts.Values)
		{
			CurvePoint point = Reference.PublicKey(k);
			byte[] expected = ReferenceEncrypt(publicKey, plaintext, k);
			byte[] der = new byte[SM2Key.GetMaxDerCiphertextLength(plaintext.Length)];
			int written = key.EncryptDer(plaintext, der, Fill(Encode(k)));

			if (!der.AsSpan(0, written).SequenceEqual(DerCiphertext(point.X, point.Y, expected.AsSpan(65, 32).ToArray(), expected.AsSpan(97).ToArray())) || DecryptDer(key, der.AsSpan(0, written).ToArray()) is null)
			{
				failures.Add($"k = {k}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(firsts.Keys).Contains((0, 0)).And.Contains((0, 1)).And.Contains((1, 0)).And.Contains((1, 1));
			await Assert.That(firsts.Keys.Any(static shape => shape.Item1 is 2)).IsTrue();
			await Assert.That(firsts.Keys.Any(static shape => shape.Item2 is 2)).IsTrue();
			await Assert.That(failures).IsEmpty();
		}
	}

	// GB/T 32918.4-2016, Sec. 6.1, A5 draws another k if t is all zero, and Sec. 7.1, B4 rejects such a t. For one byte that is a k in 256, which the reference finds.
	[Test]
	public async Task AllZeroKeyStreamsAreDrawnAgainAndRejected()
	{
		using SM2Key key = SM2Key.ImportPrivateKey(Encode(PrivateKey));
		CurvePoint publicKey = Reference.PublicKey(PrivateKey);
		CurvePoint shared = publicKey;
		BigInteger zero = 1;

		while (ReferenceKdf([.. Encode(shared.X), .. Encode(shared.Y)], 1)[0] is not 0)
		{
			shared = Reference.Add(shared, publicKey)!;
			++zero;
		}

		CurvePoint zeroShared = shared;
		BigInteger next = zero + 1;
		shared = Reference.Add(shared, publicKey)!;

		while (ReferenceKdf([.. Encode(shared.X), .. Encode(shared.Y)], 1)[0] is 0)
		{
			shared = Reference.Add(shared, publicKey)!;
			++next;
		}

		byte[] plaintext = [0x5A];
		byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(1)];
		_ = key.Encrypt(plaintext, ciphertext, Fill(Encode(zero), Encode(next)));
		byte[] der = new byte[SM2Key.GetMaxDerCiphertextLength(1)];
		int derLength = key.EncryptDer(plaintext, der, Fill(Encode(zero), Encode(next)));
		CurvePoint c1 = Reference.PublicKey(zero);
		// C2 = M ⊕ 0 and a C3 that matches.
		byte[] hash = Sm3(Encode(zeroShared.X), plaintext, Encode(zeroShared.Y));
		byte[] zeroStream = [.. EncodePoint(c1), .. hash, .. plaintext];

		using (Assert.Multiple())
		{
			await Assert.That(ciphertext).IsEquivalentTo(ReferenceEncrypt(publicKey, plaintext, next), CollectionOrdering.Matching);
			await Assert.That(DecryptDer(key, der.AsSpan(0, derLength).ToArray())).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(Decrypt(key, zeroStream)).IsNull();
			await Assert.That(DecryptDer(key, DerCiphertext(c1.X, c1.Y, hash, plaintext))).IsNull();
		}
	}

	// GB/T 32918.4 leaves no key stream for an empty plaintext.
	[Test]
	public async Task ArgumentsAreChecked()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] plaintext = new byte[10];
		byte[] ciphertext = ShortBuffer(SM2Key.GetCiphertextLength(plaintext.Length), 1);
		byte[] der = ShortBuffer(SM2Key.GetMaxDerCiphertextLength(plaintext.Length), 1);
		byte[] valid = Encrypt(key, plaintext);
		byte[] buffer = new byte[200];

		using (Assert.Multiple())
		{
			await Assert.That(SM2Key.GetCiphertextLength(1)).IsEqualTo(98);
			await Assert.That(SM2Key.GetMaxDerCiphertextLength(1)).IsEqualTo(109);
			await Assert.That(SM2Key.GetMaxDerCiphertextLength(128)).IsEqualTo(238);
			await Assert.That(() => SM2Key.GetCiphertextLength(0)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => SM2Key.GetCiphertextLength(int.MaxValue - 96)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => SM2Key.GetMaxDerCiphertextLength(0)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => SM2Key.GetMaxDerCiphertextLength(int.MaxValue - 100)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => key.Encrypt([], new byte[200])).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(() => key.EncryptDer([], new byte[200])).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(() => key.Encrypt(plaintext, ciphertext)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.EncryptDer(plaintext, der)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(ciphertext).All(static value => value is DestinationSentinel);
			await Assert.That(der).All(static value => value is DestinationSentinel);
			await Assert.That(() => key.Encrypt(buffer.AsSpan(100, 10), buffer.AsSpan(0, 107))).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.EncryptDer(buffer.AsSpan(0, 10), buffer.AsSpan(5, 120))).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.TryDecrypt(valid, new byte[plaintext.Length - 1], out _)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(key.TryDecrypt(valid, new byte[plaintext.Length], out int written)).IsTrue();
			await Assert.That(written).IsEqualTo(plaintext.Length);
		}
	}

	// The plaintext goes out only after the last read of the ciphertext, so one buffer may hold both.
	[Test]
	public async Task DecryptionMayOverwriteTheCiphertext()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[] plaintext = new byte[100];
		new Random(3).NextBytes(plaintext);
		byte[] ciphertext = Encrypt(key, plaintext);
		byte[] der = EncryptDer(key, plaintext);
		bool decrypted = key.TryDecrypt(ciphertext, ciphertext, out int written);
		bool decryptedDer = key.TryDecryptDer(der, der.AsSpan(3), out int derWritten);

		using (Assert.Multiple())
		{
			await Assert.That(decrypted).IsTrue();
			await Assert.That(ciphertext.AsSpan(0, written).ToArray()).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(decryptedDer).IsTrue();
			await Assert.That(der.AsSpan(3, derWritten).ToArray()).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task OneInstanceEncryptsAndDecryptsConcurrently()
	{
		using SM2Key key = SM2Key.GenerateKey();
		byte[][] plaintexts = [.. Enumerable.Range(1, 64).Select(static i => Enumerable.Repeat((byte)i, i).ToArray())];
		bool[] valid = new bool[plaintexts.Length];

		Parallel.For(0, plaintexts.Length, i =>
		{
			byte[]? fromRaw = Decrypt(key, Encrypt(key, plaintexts[i]));
			byte[]? fromDer = DecryptDer(key, EncryptDer(key, plaintexts[i]));
			valid[i] = fromRaw is not null && fromRaw.AsSpan().SequenceEqual(plaintexts[i]) && fromDer is not null && fromDer.AsSpan().SequenceEqual(plaintexts[i]);
		});

		await Assert.That(valid).All(static value => value);
	}

	// A key counts its encryptions in both formats and builds the table of its public key at the threshold; from the same k, the ciphertexts before and after it are those of the reference.
	[Test]
	public async Task EncryptionsBeforeAndAfterTheTableMatchTheReference()
	{
		int threshold = EncryptionTableThreshold();
		CurvePoint publicKey = Reference.PublicKey(PrivateKey);
		using SM2Key key = SM2Key.ImportPublicKey(EncodePoint(publicKey));
		Random random = new(4);
		List<string> failures = [];

		for (int i = 1; i <= 2 * threshold; ++i)
		{
			byte[] plaintext = new byte[i];
			random.NextBytes(plaintext);
			BigInteger k = ECReference.RandomBelow(random, N - 1) + 1;
			byte[] expected = ReferenceEncrypt(publicKey, plaintext, k);
			bool isDer = i % 2 is 0;
			byte[] ciphertext = new byte[isDer ? SM2Key.GetMaxDerCiphertextLength(i) : SM2Key.GetCiphertextLength(i)];
			int written = isDer ? key.EncryptDer(plaintext, ciphertext, Fill(Encode(k))) : key.Encrypt(plaintext, ciphertext, Fill(Encode(k)));
			CurvePoint c1 = Curve.DecodePoint(expected.AsSpan(0, 65));
			byte[] expectedCiphertext = isDer ? DerCiphertext(c1.X, c1.Y, expected.AsSpan(65, 32).ToArray(), expected.AsSpan(97).ToArray()) : expected;

			if (!ciphertext.AsSpan(0, written).SequenceEqual(expectedCiphertext))
			{
				failures.Add($"encryption {i}: the ciphertext differs from the reference");
			}

			if (HasTable(key) != i >= threshold)
			{
				failures.Add($"encryption {i}: the table is {(HasTable(key) ? "built" : "missing")}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// From the table, the smallest and the largest k and those whose last addition of k·P without the table meets equal points; SM2KernelTest takes the k around the windows of each kernel.
	[Test]
	public async Task EdgeEphemeralKeysEncryptFromTheTable()
	{
		CurvePoint publicKey = Reference.PublicKey(PrivateKey);
		using SM2Key key = SM2Key.ImportPublicKey(EncodePoint(publicKey));
		byte[] plaintext = [.. Enumerable.Range(0, 40).Select(static i => (byte)i)];

		for (int i = 0; i < EncryptionTableThreshold(); ++i)
		{
			_ = Encrypt(key, plaintext);
		}

		BigInteger[] scalars = [1, 2, 3, 6, N - 1, N - 2, N - 3, N - 6, N - 18, (N - 1) / 2, (N + 1) / 2];
		List<string> failures = [];

		foreach (BigInteger k in scalars)
		{
			byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(plaintext.Length)];
			_ = key.Encrypt(plaintext, ciphertext, Fill(Encode(k)));

			if (!ciphertext.AsSpan().SequenceEqual(ReferenceEncrypt(publicKey, plaintext, k)))
			{
				failures.Add($"k = {k:X}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(HasTable(key)).IsTrue();
			await Assert.That(failures).IsEmpty();
		}
	}

	// Threads that encrypt with a new key at once cross the threshold together and may each build the table; every ciphertext must still be that of the reference. Each thread meets the others once, at the barrier, before its share of the encryptions.
	[Test]
	public async Task ConcurrentEncryptionsAcrossTheThresholdMatchTheReference()
	{
		CurvePoint publicKey = Reference.PublicKey(PrivateKey);
		byte[] encodedPublicKey = EncodePoint(publicKey);
		Random random = new(5);
		(byte[] Plaintext, BigInteger K, byte[] Expected)[] cases = [.. Enumerable.Range(0, 4 * EncryptionTableThreshold()).Select(i =>
		{
			byte[] plaintext = new byte[1 + i % 70];
			random.NextBytes(plaintext);
			BigInteger k = ECReference.RandomBelow(random, N - 1) + 1;
			return (plaintext, k, ReferenceEncrypt(publicKey, plaintext, k));
		})];
		int threadCount = Math.Clamp(Environment.ProcessorCount, 2, 8);

		for (int round = 0; round < 4; ++round)
		{
			using SM2Key key = SM2Key.ImportPublicKey(encodedPublicKey);
			bool[] valid = new bool[cases.Length];
			using Barrier barrier = new(threadCount);
			Thread[] threads = [.. Enumerable.Range(0, threadCount).Select(thread => new Thread(() =>
			{
				barrier.SignalAndWait();

				for (int i = thread; i < cases.Length; i += threadCount)
				{
					(byte[] plaintext, BigInteger k, byte[] expected) = cases[i];
					byte[] ciphertext = new byte[expected.Length];

					try
					{
						_ = key.Encrypt(plaintext, ciphertext, Fill(Encode(k)));
						valid[i] = ciphertext.AsSpan().SequenceEqual(expected);
					}
					catch (Exception)
					{
						valid[i] = false;
					}
				}
			}))];

			foreach (Thread thread in threads)
			{
				thread.Start();
			}

			foreach (Thread thread in threads)
			{
				thread.Join();
			}

			using (Assert.Multiple())
			{
				await Assert.That(valid).All(static value => value);
				await Assert.That(HasTable(key)).IsTrue();
			}
		}
	}

	// Disposal drops the table, and the instance throws from then on.
	[Test]
	public async Task DisposalDropsTheTable()
	{
		SM2Key key = SM2Key.GenerateKey();
		byte[] plaintext = [1, 2, 3];

		for (int i = 0; i < EncryptionTableThreshold(); ++i)
		{
			_ = Encrypt(key, plaintext);
		}

		bool built = HasTable(key);
		key.Dispose();
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(built).IsTrue();
			await Assert.That(HasTable(key)).IsFalse();
			await Assert.That(() => key.Encrypt(plaintext, new byte[SM2Key.GetCiphertextLength(plaintext.Length)])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.EncryptDer(plaintext, new byte[SM2Key.GetMaxDerCiphertextLength(plaintext.Length)])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	private static int EncryptionTableThreshold()
	{
		return TableThreshold("EncryptionTableThreshold");
	}

	// 0 for 32 significant bytes and no sign byte, 1 with a sign byte, 2 for fewer bytes.
	private static int Shape(BigInteger coordinate)
	{
		return coordinate < BigInteger.One << 248 ? 2 : coordinate >= BigInteger.One << 255 ? 1 : 0;
	}

	private static byte[] Sequence(params byte[][] elements)
	{
		return EcdsaElement(0x30, [.. elements.SelectMany(static element => element)]);
	}

	private static byte[] DerInteger(byte[] magnitude, int padding = 0)
	{
		byte[] contents = [.. new byte[padding], .. magnitude];
		return EcdsaElement(0x02, contents);
	}

	private static byte[] Negative(byte[] magnitude)
	{
		return EcdsaElement(0x02, [(byte)(magnitude[0] | 0x80), .. magnitude.AsSpan(1)]);
	}

	private static byte[] OctetString(byte[] contents)
	{
		return EcdsaElement(0x04, contents);
	}

	private static byte[] EcdsaElement(byte tag, byte[] contents)
	{
		return EcdsaTestUtils.Element(tag, contents);
	}

	// The contents of the INTEGERs and OCTET STRINGs of an SM2Cipher.
	private sealed record AsnParts(byte[] X, byte[] Y, byte[] Hash, byte[] CipherText)
	{
		public static AsnParts Read(byte[] der)
		{
			AsnReader sequence = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
			return new AsnParts(sequence.ReadIntegerBytes().ToArray(), sequence.ReadIntegerBytes().ToArray(), sequence.ReadOctetString(), sequence.ReadOctetString());
		}
	}
}
