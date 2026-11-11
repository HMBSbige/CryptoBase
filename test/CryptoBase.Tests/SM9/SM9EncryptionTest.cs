using CryptoBase.EllipticCurves.SM9;
using CryptoBase.SM9;
using CryptoBase.Tests.EllipticCurves;
using CryptoBase.Tests.EllipticCurves.SM9;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Reflection;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.SM9.SM9TestUtils;
using static CryptoBase.Tests.TestUtils;
using SM9EllipticCurveTestUtils = CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;

namespace CryptoBase.Tests.SM9;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class SM9EncryptionTest
{
	private static readonly byte[] Bob = "Bob"u8.ToArray();

	// Plaintexts around the KDF block of 32 bytes and K2 at every offset in it, and one long enough for a pooled buffer, as C1 ‖ C3 ‖ C2 and in DER, from the master public key alone.
	[Test]
	public async Task CiphertextsDecrypt()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(master));
		List<string> failures = [];

		foreach (byte[] id in (byte[][])[[], Bob, [.. Enumerable.Range(0, 300).Select(static i => (byte)i)]])
		{
			using SM9EncryptionKey key = master.ExtractKey(id);

			foreach (int length in (int[])[1, 2, 31, 32, 33, 63, 64, 65, 255, 1000, 70000])
			{
				byte[] plaintext = CreateDeterministicSource(length);
				byte[] ciphertext = Encrypt(sender, plaintext, id);
				byte[] der = EncryptDer(sender, plaintext, id);

				if (ciphertext.Length != length + 96 || Decrypt(key, ciphertext) is not { } decrypted || !decrypted.AsSpan().SequenceEqual(plaintext)
					|| DecryptDer(key, der) is not { } fromDer || !fromDer.AsSpan().SequenceEqual(plaintext) || der.Length != SM9EncryptionMasterKey.GetDerCiphertextLength(length))
				{
					failures.Add($"ID of {id.Length} bytes, plaintext of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Keys of one byte to several KDF blocks.
	[Test]
	public async Task EncapsulationsDecapsulate()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(master));
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		List<string> failures = [];

		foreach (int length in (int[])[1, 16, 31, 32, 33, 64, 100])
		{
			byte[] encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
			byte[] sharedKey = new byte[length];
			sender.Encapsulate(encapsulation, sharedKey, Bob);

			if (Decapsulate(key, encapsulation, length) is not { } recovered || !recovered.AsSpan().SequenceEqual(sharedKey) || encapsulation[0] is not 0x04)
			{
				failures.Add($"a key of {length} bytes");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The key derivation takes the ID, so a ciphertext for another ID or of another master key does not decrypt, and an encapsulation gives another key.
	[Test]
	public async Task OtherIdsAndKeysFail()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionMasterKey other = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionKey bob = master.ExtractKey(Bob);
		using SM9EncryptionKey carol = master.ExtractKey("Carol"u8);
		using SM9EncryptionKey otherBob = other.ExtractKey(Bob);
		byte[] plaintext = "plaintext"u8.ToArray();
		byte[] ciphertext = Encrypt(master, plaintext, Bob);
		byte[] encapsulation = new byte[65];
		byte[] sharedKey = new byte[32];
		master.Encapsulate(encapsulation, sharedKey, Bob);

		using (Assert.Multiple())
		{
			await Assert.That(Decrypt(bob, ciphertext)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(Decrypt(carol, ciphertext)).IsNull();
			await Assert.That(Decrypt(otherBob, ciphertext)).IsNull();
			await Assert.That(Decrypt(bob, Encrypt(master, plaintext, "Bob\0"u8.ToArray()))).IsNull();
			await Assert.That(Decapsulate(bob, encapsulation, 32)).IsEquivalentTo(sharedKey, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(carol, encapsulation, 32)).IsNotEquivalentTo(sharedKey);
			await Assert.That(Decapsulate(otherBob, encapsulation, 32)).IsNotEquivalentTo(sharedKey);
		}
	}

	// GM/T 0044.4-2016, Sec. 7.2: C1 must be a point on the curve and C3 must match; any changed byte fails, as do other lengths, and the destination keeps every byte.
	[Test]
	public async Task TamperedCiphertextsFail()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] plaintext = "plain"u8.ToArray();
		byte[] ciphertext = Encrypt(master, plaintext, Bob);
		BigInteger x = new(ciphertext.AsSpan(0, 32), true, true);
		BigInteger y = new(ciphertext.AsSpan(32, 32), true, true);
		List<byte[]> invalid = [[], ciphertext.AsSpan(0, 96).ToArray(), ciphertext.AsSpan(0, 100).ToArray(), [.. ciphertext, 0], [0x04, .. ciphertext], [.. new byte[64], .. ciphertext.AsSpan(64)], [.. Encode(x), .. Encode((y + 1) % P), .. ciphertext.AsSpan(64)], [.. Encode(P), .. Encode(y), .. ciphertext.AsSpan(64)]];

		for (int i = 0; i < ciphertext.Length; ++i)
		{
			invalid.Add(Flip(ciphertext, i));
		}

		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			byte[] destination = CreateGuardedBuffer(0, Math.Max(encoding.Length, 1));

			if (key.TryDecrypt(encoding, destination, out int written) || written is not 0 || destination.AsSpan().ContainsAnyExcept(DestinationSentinel))
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(Decrypt(key, ciphertext)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}

	// The SM9Cipher of GB/T 41389-2022 in DER with EnType 0 alone: other types, encodings of C1 and lengths of C3, trailing bytes, an empty C2 and other forms of DER fail.
	[Test]
	public async Task InvalidDerCiphertextsFail()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] plaintext = "plaintext"u8.ToArray();
		byte[] raw = Encrypt(master, plaintext, Bob);
		byte[] c1 = [0x04, .. raw.AsSpan(0, 64)];
		byte[] c3 = raw.AsSpan(64, 32).ToArray();
		byte[] c2 = raw.AsSpan(96).ToArray();
		byte[] valid = Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2));
		byte[][] invalid =
		[
			[], [.. valid, 0], valid.AsSpan(0, valid.Length - 1).ToArray(), raw,
			Cipher([0x02, 0x01, 0x01], BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2)), Cipher([0x02, 0x01, 0x02], BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2)), Cipher([0x02, 0x01, 0xFF], BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2)),
			Cipher([0x02, 0x02, 0x00, 0x00], BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2)), Cipher(BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2)),
			Cipher([0x02, 0x01, 0x00], [0x03, 0x42, 0x01, .. c1], Tlv(0x04, c3), Tlv(0x04, c2)), Cipher([0x02, 0x01, 0x00], BitString(c1.AsSpan(1).ToArray()), Tlv(0x04, c3), Tlv(0x04, c2)),
			Cipher([0x02, 0x01, 0x00], BitString([0x02, .. c1.AsSpan(1, 32)]), Tlv(0x04, c3), Tlv(0x04, c2)), Cipher([0x02, 0x01, 0x00], Tlv(0x04, c1), Tlv(0x04, c3), Tlv(0x04, c2)),
			Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3.AsSpan(1).ToArray()), Tlv(0x04, c2)), Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, [.. c3, 0]), Tlv(0x04, c2)),
			Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3), Tlv(0x04, [])), Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3)), Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3), Tlv(0x04, c2), [0x05, 0x00]),
			Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c2), Tlv(0x04, c3)), Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3), [0x04, 0x81, (byte)c2.Length, .. c2]),
			[0x30, 0x81, (byte)(valid.Length - 2), .. valid.AsSpan(2)], [0x30, 0x80, .. valid.AsSpan(2), 0x00, 0x00], Cipher([0x02, 0x01, 0x00], BitString(c1), Tlv(0x04, c3), [0x24, (byte)(c2.Length + 2), .. Tlv(0x04, c2)]),
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			byte[] destination = CreateGuardedBuffer(0, Math.Max(encoding.Length, 1));

			if (key.TryDecryptDer(encoding, destination, out int written) || written is not 0 || destination.AsSpan().ContainsAnyExcept(DestinationSentinel))
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(DecryptDer(key, valid)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}

	// GM/T 0044.4-2016, Sec. 6.1 and 7.1, draw another r if K, or K1, is all zero, and the decryptor rejects such a key, here of one byte, which an r of the search makes zero.
	[Test]
	public async Task AllZeroKeysAreDrawnAgainAndRejected()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Encode(0x5EED));
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		BigInteger zero = 1;

		// The encapsulation of one byte draws again for this r, and the randomness runs out.
		while (!DrawsAgain(master, zero))
		{
			++zero;
		}

		BigInteger other = zero + 1;

		while (DrawsAgain(master, other))
		{
			++other;
		}

		byte[] expected = Encapsulate(master, 1, Fill(Encode(other)), out byte[] expectedKey);
		byte[] encapsulation = Encapsulate(master, 1, Fill(Encode(zero), Encode(other)), out byte[] sharedKey);
		G1Value publicKey = new(new BigInteger(ExportPublicKey(master).AsSpan(1, 32), true, true), new BigInteger(ExportPublicKey(master).AsSpan(33, 32), true, true));
		byte[] c = EncodePoint(Multiply(Add(Multiply(P1, ReferenceHash(0x01, [.. Bob, 0x03])), publicKey), zero)!);
		byte[] k = Decapsulate(key, c, 33)!;
		byte[] c2 = [0x5A];
		byte[] ciphertext = [.. c.AsSpan(1), .. Sm3(c2, k.AsSpan(1).ToArray()), .. c2];
		byte[] encrypted = new byte[97];
		master.Encrypt([0x5A], encrypted, Bob, Fill(Encode(zero), Encode(other)));

		using (Assert.Multiple())
		{
			await Assert.That(encapsulation).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(sharedKey).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(k[0]).IsEqualTo((byte)0);
			await Assert.That(Decapsulate(key, c, 1)).IsNull();
			await Assert.That(Decapsulate(key, c, 2)).IsNotNull();
			await Assert.That(Decrypt(key, ciphertext)).IsNull();
			await Assert.That(encrypted.AsSpan(0, 64).ToArray()).IsEquivalentTo(expected.AsSpan(1).ToArray(), CollectionOrdering.Matching);
			await Assert.That(Decrypt(key, encrypted)).IsEquivalentTo((byte[])[0x5A], CollectionOrdering.Matching);
		}

		static bool DrawsAgain(SM9EncryptionMasterKey master, BigInteger r)
		{
			try
			{
				_ = Encapsulate(master, 1, Fill(Encode(r)), out _);
				return false;
			}
			catch (InvalidOperationException)
			{
				return true;
			}
		}
	}

	// An exported key imports with its master public key and ID, and the import checks that it is that of the ID under the master key; a key exchange key of the same ID is another key.
	[Test]
	public async Task PrivateKeysImportForTheirIdAlone()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionMasterKey other = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		using SM9KeyExchangeKey exchangeKey = master.ExtractKeyExchangeKey(Bob);
		byte[] privateKey = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(master);
		using SM9EncryptionKey imported = SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey, Bob);
		byte[] plaintext = "plaintext"u8.ToArray();

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(exchangeKey)).IsNotEquivalentTo(privateKey);
			await Assert.That(Decrypt(imported, Encrypt(master, plaintext, Bob))).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey, "Carol"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(privateKey, ExportPublicKey(other), Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(ExportPrivateKey(exchangeKey), publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9KeyExchangeKey.ImportPrivateKey(privateKey, publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(EncodeTwistPointOutsideG2(), publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(privateKey.AsSpan(1), publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey.AsSpan(1), Bob)).Throws<ArgumentException>().WithParameterName("masterPublicKey");
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(privateKey, [0x04, .. new byte[64]], Bob)).Throws<ArgumentException>().WithParameterName("masterPublicKey");
		}
	}

	// For any hid, the keys are those of GM/T 0044.4, Sec. 5.3, and import with that hid, and a sender of that hid encrypts, as C1 ‖ C3 ‖ C2 and in DER, and encapsulates to them; a sender of another hid gives ciphertexts that do not decrypt and encapsulations of other keys, and the import with another hid throws.
	[Test]
	public async Task OtherHidsEncryptAndDecrypt()
	{
		Random random = new(11);
		byte[] plaintext = "plaintext"u8.ToArray();
		List<string> failures = [];

		foreach (byte hid in (byte[])[0x00, 0x02, 0x05, 0x80, 0xFF])
		{
			BigInteger ke = RandomScalar(random);
			using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Encode(ke), hid);
			byte[] publicKey = ExportPublicKey(master);
			using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(publicKey, hid);
			using SM9EncryptionMasterKey other = SM9EncryptionMasterKey.ImportPublicKey(publicKey, (byte)(hid ^ 1));
			using SM9EncryptionKey key = master.ExtractKey(Bob);
			byte[] privateKey = ExportPrivateKey(key);
			BigInteger h1 = ReferenceHash(0x01, [.. Bob, hid]);
			using SM9EncryptionKey imported = SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey, Bob, hid);
			byte[] encapsulation = new byte[65];
			byte[] sharedKey = new byte[32];
			sender.Encapsulate(encapsulation, sharedKey, Bob);
			byte[] otherEncapsulation = new byte[65];
			byte[] otherKey = new byte[32];
			other.Encapsulate(otherEncapsulation, otherKey, Bob);

			if (!privateKey.AsSpan().SequenceEqual(EncodePoint(Multiply(P2, ke * ECReference.Inverse((h1 + ke) % N, N) % N)!))
				|| master.Hid != hid || sender.Hid != hid
				|| Decrypt(key, Encrypt(sender, plaintext, Bob)) is not { } decrypted || !decrypted.AsSpan().SequenceEqual(plaintext)
				|| DecryptDer(imported, EncryptDer(master, plaintext, Bob)) is not { } fromDer || !fromDer.AsSpan().SequenceEqual(plaintext)
				|| Decapsulate(imported, encapsulation, 32) is not { } recovered || !recovered.AsSpan().SequenceEqual(sharedKey)
				|| Decrypt(key, Encrypt(other, plaintext, Bob)) is not null || DecryptDer(key, EncryptDer(other, plaintext, Bob)) is not null
				|| Decapsulate(key, otherEncapsulation, 32) is { } wrong && wrong.AsSpan().SequenceEqual(otherKey)
				|| !ImportThrows(() => SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey, Bob, (byte)(hid ^ 1))))
			{
				failures.Add($"hid {hid:X2}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The default hid is 0x03 and leaves the master public key unchanged: a key of another hid neither decrypts what a default sender encrypts nor imports by default, and the key exchange key of hid 0x03 is the decryption key.
	[Test]
	public async Task HidIsThreeByDefault()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		byte[] privateKey = new byte[32];
		master.ExportPrivateKey(privateKey);
		byte[] publicKey = ExportPublicKey(master);
		using SM9EncryptionMasterKey imported = SM9EncryptionMasterKey.ImportPrivateKey(privateKey);
		using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(publicKey);
		using SM9EncryptionMasterKey other = SM9EncryptionMasterKey.ImportPrivateKey(privateKey, 0x05);
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		using SM9EncryptionKey otherKey = other.ExtractKey(Bob);
		using SM9KeyExchangeKey exchangeKey = master.ExtractKeyExchangeKey(Bob, 0x03);
		byte[] plaintext = "plaintext"u8.ToArray();
		byte[] otherPrivateKey = ExportPrivateKey(otherKey);

		using (Assert.Multiple())
		{
			await Assert.That(master.Hid).IsEqualTo((byte)0x03);
			await Assert.That(imported.Hid).IsEqualTo((byte)0x03);
			await Assert.That(sender.Hid).IsEqualTo((byte)0x03);
			await Assert.That(other.Hid).IsEqualTo((byte)0x05);
			await Assert.That(ExportPublicKey(other)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(otherPrivateKey).IsNotEquivalentTo(ExportPrivateKey(key));
			await Assert.That(ExportPrivateKey(exchangeKey)).IsEquivalentTo(ExportPrivateKey(key), CollectionOrdering.Matching);
			await Assert.That(Decrypt(key, Encrypt(sender, plaintext, Bob))).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(Decrypt(otherKey, Encrypt(sender, plaintext, Bob))).IsNull();
			await Assert.That(Decrypt(otherKey, Encrypt(other, plaintext, Bob))).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(otherPrivateKey, publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
		}
	}

	[Test]
	public async Task ArgumentsAreChecked()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] ciphertext = Encrypt(master, [1, 2, 3], Bob);
		byte[] buffer = new byte[200];

		using (Assert.Multiple())
		{
			await Assert.That(SM9EncryptionMasterKey.GetCiphertextLength(1)).IsEqualTo(97);
			await Assert.That(SM9EncryptionMasterKey.GetDerCiphertextLength(1)).IsEqualTo(110);
			await Assert.That(SM9EncryptionMasterKey.GetDerCiphertextLength(128)).IsEqualTo(239);
			await Assert.That(() => SM9EncryptionMasterKey.GetCiphertextLength(0)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => SM9EncryptionMasterKey.GetCiphertextLength(int.MaxValue - 95)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => SM9EncryptionMasterKey.GetDerCiphertextLength(0)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => SM9EncryptionMasterKey.GetDerCiphertextLength(int.MaxValue)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => master.Encrypt([], new byte[96], Bob)).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(() => master.EncryptDer([], new byte[200], Bob)).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(() => master.Encrypt([1], new byte[96], Bob)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => master.EncryptDer([1], new byte[107], Bob)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => master.Encrypt(buffer.AsSpan(0, 10), buffer.AsSpan(5, 106), Bob)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => master.Encapsulate(new byte[64], new byte[16], Bob)).Throws<ArgumentException>().WithParameterName("encapsulation");
			await Assert.That(() => master.Encapsulate(new byte[65], [], Bob)).Throws<ArgumentException>().WithParameterName("key");
			await Assert.That(() => master.Encapsulate(buffer.AsSpan(0, 65), buffer.AsSpan(64, 16), Bob)).Throws<ArgumentException>();
			await Assert.That(() => key.TryDecapsulate(new byte[65], [])).Throws<ArgumentException>().WithParameterName("key");
			await Assert.That(() => key.TryDecrypt(ciphertext, new byte[2], out _)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.ExportPrivateKey(new byte[128])).Throws<ArgumentException>().WithParameterName("destination");
		}
	}

	// The output may overwrite the ciphertext as it decrypts, and the encapsulation the key of a decapsulation.
	[Test]
	public async Task DecryptionMayOverlapTheCiphertext()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] plaintext = CreateDeterministicSource(100);
		byte[] ciphertext = Encrypt(master, plaintext, Bob);
		byte[] shifted = [.. new byte[10], .. ciphertext];
		byte[] encapsulation = new byte[65];
		byte[] sharedKey = new byte[64];
		master.Encapsulate(encapsulation, sharedKey, Bob);
		byte[] buffer = [.. encapsulation];

		using (Assert.Multiple())
		{
			await Assert.That(key.TryDecrypt(ciphertext, ciphertext, out int written)).IsTrue();
			await Assert.That(ciphertext.AsSpan(0, written).ToArray()).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(key.TryDecrypt(shifted.AsSpan(10), shifted.AsSpan(20), out written)).IsTrue();
			await Assert.That(shifted.AsSpan(20, written).ToArray()).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(key.TryDecapsulate(buffer, buffer.AsSpan(1, 64))).IsTrue();
			await Assert.That(buffer.AsSpan(1).ToArray()).IsEquivalentTo(sharedKey, CollectionOrdering.Matching);
		}
	}

	// The first decryption builds the lines of de and the first encryption g = e(Ppub-e, P2), and the second its table, on several threads at once.
	[Test]
	public async Task OneInstanceEncryptsAndDecryptsConcurrently()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		byte[] publicKey = ExportPublicKey(master);
		byte[][] plaintexts = [.. Enumerable.Range(1, 32).Select(CreateDeterministicSource)];

		for (int round = 0; round < 3; ++round)
		{
			using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(publicKey);
			using SM9EncryptionKey key = master.ExtractKey(Bob);
			bool[] valid = new bool[plaintexts.Length];
			Parallel.For(0, plaintexts.Length, i =>
			{
				byte[] encapsulation = new byte[65];
				byte[] sharedKey = new byte[16];
				sender.Encapsulate(encapsulation, sharedKey, Bob);
				valid[i] = Decrypt(key, Encrypt(sender, plaintexts[i], Bob)) is { } decrypted && decrypted.AsSpan().SequenceEqual(plaintexts[i]) && Decapsulate(key, encapsulation, 16) is { } recovered && recovered.AsSpan().SequenceEqual(sharedKey);
			});

			await Assert.That(valid).All(static value => value);
		}
	}

	[Test]
	public async Task DisposedKeysThrow()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] ciphertext = Encrypt(master, [1], Bob);
		_ = Decrypt(key, ciphertext);
		object privateKey = typeof(SM9EncryptionKey).GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(key)!;
		object lines = typeof(SM9G2PrivateKey).GetField("_lines", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(privateKey)!;
		SM9PrecomputedLine[] stored = (SM9PrecomputedLine[])typeof(SM9PairingLines).GetField("_lines", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(lines)!;
		key.Dispose();
		key.Dispose();
		SM9AffinePoint<SM9Fp2> point = (SM9AffinePoint<SM9Fp2>)typeof(SM9G2PrivateKey).GetField("_point", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(privateKey)!;

		using (Assert.Multiple())
		{
			await Assert.That(IsZero(in point)).IsTrue();
			await Assert.That(stored).All(static line => SM9EllipticCurveTestUtils.RawValue(line.A.A0).IsZero && SM9EllipticCurveTestUtils.RawValue(line.A.A1).IsZero && SM9EllipticCurveTestUtils.RawValue(line.B.A0).IsZero && SM9EllipticCurveTestUtils.RawValue(line.B.A1).IsZero);
			await Assert.That(() => key.TryDecrypt(ciphertext, new byte[1], out _)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.TryDecryptDer(ciphertext, new byte[1], out _)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.TryDecapsulate(new byte[65], new byte[1])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPrivateKey(new byte[129])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// C = [r]QB for QB = [H1(ID_B ‖ hid, N)]P1 + Ppub-e, for one r from encapsulations before and after the master public key builds the table of Ppub-e, and with the master private key.
	[Test]
	public async Task EncapsulationsAgreeBeforeAndAfterTheTable()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Encode(0x5EED));
		using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(master));
		BigInteger r = Parse("1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F80");
		G1Value publicKey = new(new BigInteger(ExportPublicKey(master).AsSpan(1, 32), true, true), new BigInteger(ExportPublicKey(master).AsSpan(33, 32), true, true));
		byte[] expected = EncodePoint(Multiply(Add(Multiply(P1, ReferenceHash(0x01, [.. Bob, 0x03])), publicKey), r)!);
		bool same = true;

		for (int i = 0; i < SM9G1FixedBase.TableThreshold + 2; ++i)
		{
			same &= Encapsulate(sender, 16, Fill(Encode(r)), out _).AsSpan().SequenceEqual(expected);
			same &= Encapsulate(master, 16, Fill(Encode(r)), out _).AsSpan().SequenceEqual(expected);
		}

		await Assert.That(same).IsTrue();
	}

	private static byte[] Encapsulate(SM9EncryptionMasterKey master, int length, Action<Span<byte>> fill, out byte[] sharedKey)
	{
		byte[] encapsulation = new byte[65];
		sharedKey = new byte[length];
		master.Encapsulate(encapsulation, sharedKey, Bob, fill);
		return encapsulation;
	}

	private static byte[] BitString(byte[] contents)
	{
		return Tlv(0x03, [0x00], contents);
	}

	private static byte[] Cipher(params byte[][] contents)
	{
		return Sequence(contents);
	}
}
