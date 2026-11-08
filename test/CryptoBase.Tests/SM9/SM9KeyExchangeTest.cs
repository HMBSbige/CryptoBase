using CryptoBase.SM9;
using CryptoBase.Tests.EllipticCurves.SM9;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.SM9.SM9TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SM9;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class SM9KeyExchangeTest
{
	private static readonly byte[] Alice = "Alice"u8.ToArray();

	private static readonly byte[] Bob = "Bob"u8.ToArray();

	// Both parties derive one key and confirm each other, for keys of one byte to several blocks of the KDF and IDs from empty to long.
	[Test]
	public async Task PartiesAgree()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		List<string> failures = [];

		foreach ((byte[] idA, byte[] idB) in ((byte[], byte[])[])[([], [0]), (Alice, Bob), ([.. Enumerable.Range(0, 500).Select(static i => (byte)i)], Bob)])
		{
			using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(idA);
			using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(idB);

			foreach (int length in (int[])[1, 16, 31, 32, 33, 100])
			{
				(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(a, idA, b, idB, length);

				if (!keyA.AsSpan().SequenceEqual(keyB) || !confirmed)
				{
					failures.Add($"IDs of {idA.Length} and {idB.Length} bytes, a key of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The key and the confirmations hash both IDs and both ephemeral keys, in the order of the roles, and take the keys of one master key.
	[Test]
	public async Task MismatchesGiveOtherKeys()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9EncryptionMasterKey other = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		using SM9KeyExchangeKey otherB = other.ExtractKeyExchangeKey(Bob);
		(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(a, Alice, b, Bob, 16);
		// The responder takes the initiator to be Carol.
		(byte[] carolA, byte[] carolB, bool carolConfirmed) = Exchange(a, "Carol"u8.ToArray(), b, Bob, 16);
		(byte[] otherA, byte[] otherKeyB, bool otherConfirmed) = Exchange(a, Alice, otherB, Bob, 16);
		// Both take the initiator role.
		using SM9KeyExchange first = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange second = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Initiator);
		byte[] firstKey = new byte[16];
		byte[] secondKey = new byte[16];
		bool firstDerived = first.TryDeriveKey(ExportEphemeral(second), firstKey);
		bool secondDerived = second.TryDeriveKey(ExportEphemeral(first), secondKey);

		using (Assert.Multiple())
		{
			await Assert.That(keyA).IsEquivalentTo(keyB, CollectionOrdering.Matching);
			await Assert.That(confirmed).IsTrue();
			await Assert.That(carolA).IsNotEquivalentTo(carolB);
			await Assert.That(carolConfirmed).IsFalse();
			await Assert.That(otherA).IsNotEquivalentTo(otherKeyB);
			await Assert.That(otherConfirmed).IsFalse();
			await Assert.That(firstDerived && secondDerived).IsTrue();
			await Assert.That(firstKey).IsNotEquivalentTo(secondKey);
		}
	}

	// GM/T 0044.3-2016, Sec. 6.1, A5 and B4: the ephemeral key of the peer must be a point of G1, here uncompressed. The derivation then fails, writes nothing and may be tried again.
	[Test]
	public async Task InvalidEphemeralKeysFail()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		using SM9KeyExchange initiator = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Responder);
		byte[] valid = ExportEphemeral(initiator);
		BigInteger x = new(valid.AsSpan(1, 32), true, true);
		BigInteger y = new(valid.AsSpan(33, 32), true, true);
		byte[][] invalid =
		[
			[], valid.AsSpan(1).ToArray(), [.. valid, 0], [0x02, .. valid.AsSpan(1, 32)], [0x03, .. valid.AsSpan(1)], [0x00, .. valid.AsSpan(1)], [0x06, .. valid.AsSpan(1)],
			new byte[65], [0x04, .. new byte[64]], [0x04, .. Encode(x), .. Encode((y + 1) % P)], [0x04, .. Encode(P), .. Encode(y)], [0x04, .. Encode(x), .. Encode(P)],
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			byte[] key = CreateGuardedBuffer(0, 16);
			byte[] confirmation = CreateGuardedBuffer(0, 32);
			byte[] peerConfirmation = CreateGuardedBuffer(0, 32);

			if (responder.TryDeriveKey(encoding, key, confirmation, peerConfirmation) || ((byte[][])[key, confirmation, peerConfirmation]).Any(static output => output.AsSpan().ContainsAnyExcept(DestinationSentinel)))
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(responder.TryDeriveKey(valid, new byte[16])).IsTrue();
		}
	}

	// A successful derivation erases the secrets of the instance, so an ephemeral key serves one exchange.
	[Test]
	public async Task InstancesDeriveOnce()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		using SM9KeyExchange initiator = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Responder);
		byte[] ephemeralB = ExportEphemeral(responder);

		using (Assert.Multiple())
		{
			await Assert.That(initiator.TryDeriveKey(ephemeralB, new byte[16])).IsTrue();
			await Assert.That(() => initiator.TryDeriveKey(ephemeralB, new byte[16])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(ExportEphemeral(initiator).Length).IsEqualTo(65);
		}
	}

	[Test]
	public async Task ArgumentsAreChecked()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		SM9KeyExchangeKey disposed = master.ExtractKeyExchangeKey(Bob);
		disposed.Dispose();
		using SM9KeyExchange initiator = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Responder);
		byte[] ephemeral = ExportEphemeral(responder);
		byte[] buffer = new byte[64];

		using (Assert.Multiple())
		{
			await Assert.That(SM9KeyExchange.EphemeralPublicKeyLength).IsEqualTo(65);
			await Assert.That(SM9KeyExchange.ConfirmationLength).IsEqualTo(32);
			await Assert.That(() => SM9KeyExchange.Create(null!, Bob, SM9KeyExchangeRole.Initiator)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => SM9KeyExchange.Create(disposed, Alice, SM9KeyExchangeRole.Initiator)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => SM9KeyExchange.Create(a, Bob, (SM9KeyExchangeRole)2)).Throws<ArgumentOutOfRangeException>().WithParameterName("role");
			await Assert.That(() => initiator.TryDeriveKey(ephemeral, [])).Throws<ArgumentOutOfRangeException>().WithParameterName("sharedKey");
			await Assert.That(() => initiator.TryDeriveKey(ephemeral, new byte[16], new byte[31], new byte[32])).Throws<ArgumentException>().WithParameterName("confirmation");
			await Assert.That(() => initiator.TryDeriveKey(ephemeral, new byte[16], new byte[32], new byte[31])).Throws<ArgumentException>().WithParameterName("peerConfirmation");
			await Assert.That(() => initiator.TryDeriveKey(ephemeral, buffer.AsSpan(0, 16), buffer.AsSpan(8, 32), new byte[32])).Throws<ArgumentException>();
			await Assert.That(() => initiator.TryDeriveKey(ephemeral, new byte[16], buffer.AsSpan(0, 32), buffer.AsSpan(31, 32))).Throws<ArgumentException>();
			await Assert.That(() => initiator.ExportEphemeralPublicKey(new byte[64])).Throws<ArgumentException>().WithParameterName("destination");
		}
	}

	// The input is read before any output is written, so it may share a buffer with the outputs: here the ephemeral key of the peer lies under the key and the confirmation.
	[Test]
	public async Task InputsMayOverlapTheOutputs()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		using SM9KeyExchange initiator = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Responder);
		byte[] ephemeralA = ExportEphemeral(initiator);
		byte[] keyB = new byte[48];
		byte[] sB = new byte[32];
		byte[] s2 = new byte[32];
		bool derivedB = responder.TryDeriveKey(ephemeralA, keyB, sB, s2);
		byte[] buffer = [.. ExportEphemeral(responder), .. new byte[47]];
		bool derivedA = initiator.TryDeriveKey(buffer.AsSpan(0, 65), buffer.AsSpan(0, 48), buffer.AsSpan(48, 32), buffer.AsSpan(80, 32));

		using (Assert.Multiple())
		{
			await Assert.That(derivedB).IsTrue();
			await Assert.That(derivedA).IsTrue();
			await Assert.That(buffer.AsSpan(0, 48).ToArray()).IsEquivalentTo(keyB, CollectionOrdering.Matching);
			await Assert.That(buffer.AsSpan(48, 32).ToArray()).IsEquivalentTo(s2, CollectionOrdering.Matching);
			await Assert.That(buffer.AsSpan(80, 32).ToArray()).IsEquivalentTo(sB, CollectionOrdering.Matching);
		}
	}

	// An exported key imports with its master public key and ID, and the import checks that it is that of the ID, with hid = 0x02, under the master key.
	[Test]
	public async Task PrivateKeysImportForTheirIdAlone()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		byte[] publicKey = ExportPublicKey(master);
		using SM9KeyExchangeKey imported = SM9KeyExchangeKey.ImportPrivateKey(ExportPrivateKey(a), publicKey, Alice);
		(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(imported, Alice, b, Bob, 16);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(ExportPrivateKey(a), CollectionOrdering.Matching);
			await Assert.That(keyA).IsEquivalentTo(keyB, CollectionOrdering.Matching);
			await Assert.That(confirmed).IsTrue();
			await Assert.That(() => SM9KeyExchangeKey.ImportPrivateKey(ExportPrivateKey(a), publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9KeyExchangeKey.ImportPrivateKey(EncodeTwistPointOutsideG2(), publicKey, Alice)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9KeyExchangeKey.ImportPrivateKey(ExportPrivateKey(a), publicKey.AsSpan(1), Alice)).Throws<ArgumentException>().WithParameterName("masterPublicKey");
		}
	}

	// The KGC may choose any hid for the key exchange: keys of one hid agree, with and without confirmation, and import only with it; with keys of two hids, each party takes the user public key of its peer under its own hid, so the keys and the confirmations differ.
	[Test]
	public async Task OtherHidsAgree()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		byte[] publicKey = ExportPublicKey(master);
		List<string> failures = [];

		foreach (byte hid in (byte[])[0x00, 0x03, 0x05, 0x80, 0xFF])
		{
			using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice, hid);
			using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob, hid);
			byte[] privateKeyB = ExportPrivateKey(b);
			using SM9KeyExchangeKey importedB = SM9KeyExchangeKey.ImportPrivateKey(privateKeyB, publicKey, Bob, hid);
			using SM9KeyExchangeKey otherB = master.ExtractKeyExchangeKey(Bob, (byte)(hid ^ 1));
			(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(a, Alice, importedB, Bob, 16);
			(byte[] otherA, byte[] otherKeyB, bool otherConfirmed) = Exchange(a, Alice, otherB, Bob, 16);
			using SM9KeyExchange initiator = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
			using SM9KeyExchange responder = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Responder);
			byte[] unconfirmedA = new byte[24];
			byte[] unconfirmedB = new byte[24];

			if (!keyA.AsSpan().SequenceEqual(keyB) || !confirmed || otherA.AsSpan().SequenceEqual(otherKeyB) || otherConfirmed
				|| !responder.TryDeriveKey(ExportEphemeral(initiator), unconfirmedB) || !initiator.TryDeriveKey(ExportEphemeral(responder), unconfirmedA) || !unconfirmedA.AsSpan().SequenceEqual(unconfirmedB)
				|| !ImportThrows(() => SM9KeyExchangeKey.ImportPrivateKey(privateKeyB, publicKey, Bob, (byte)(hid ^ 1))))
			{
				failures.Add($"hid {hid:X2}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A disposed instance throws, as does a derivation once its key exchange key has been disposed.
	[Test]
	public async Task DisposedInstancesThrow()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		SM9KeyExchange exchange = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(b, Alice, SM9KeyExchangeRole.Responder);
		byte[] ephemeral = ExportEphemeral(exchange);
		exchange.Dispose();
		exchange.Dispose();
		b.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => exchange.ExportEphemeralPublicKey(new byte[65])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => exchange.TryDeriveKey(ephemeral, new byte[16])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => responder.TryDeriveKey(ephemeral, new byte[16])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => b.ExportPrivateKey(new byte[129])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// One key exchange key serves many exchanges at once; the first builds the lines of de and the table of g.
	[Test]
	public async Task OneKeyServesConcurrentExchanges()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey b = master.ExtractKeyExchangeKey(Bob);
		bool[] agreed = new bool[16];
		Parallel.For(0, agreed.Length, i =>
		{
			(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(a, Alice, b, Bob, 16 + i);
			agreed[i] = keyA.AsSpan().SequenceEqual(keyB) && confirmed;
		});

		await Assert.That(agreed).All(static value => value);
	}

	// R_A = [r]Q_B for Q_B = [H1(ID_B ‖ hid, N)]P1 + Ppub-e, for one r from exchanges before and after the key exchange key builds the table of Ppub-e.
	[Test]
	public async Task EphemeralKeysAgreeBeforeAndAfterTheTable()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Encode(0x5EED));
		using SM9KeyExchangeKey a = master.ExtractKeyExchangeKey(Alice);
		BigInteger r = Parse("1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F80");
		G1Value publicKey = new(new BigInteger(ExportPublicKey(master).AsSpan(1, 32), true, true), new BigInteger(ExportPublicKey(master).AsSpan(33, 32), true, true));
		byte[] expected = EncodePoint(Multiply(Add(Multiply(P1, ReferenceHash(0x01, [.. Bob, 0x02])), publicKey), r)!);
		bool same = true;

		for (int i = 0; i < SM9G1FixedBase.TableThreshold + 2; ++i)
		{
			using SM9KeyExchange initiator = SM9KeyExchange.Create(a, Bob, SM9KeyExchangeRole.Initiator, Fill(Encode(r)));
			same &= ExportEphemeral(initiator).AsSpan().SequenceEqual(expected);
		}

		await Assert.That(same).IsTrue();
	}

	// The keys of both parties and whether each confirmation matches the one its peer expects, for idA, the ID of the initiator as the responder takes it, and idB, that of the responder.
	private static (byte[] KeyA, byte[] KeyB, bool Confirmed) Exchange(SM9KeyExchangeKey a, byte[] idA, SM9KeyExchangeKey b, byte[] idB, int length)
	{
		using SM9KeyExchange initiator = SM9KeyExchange.Create(a, idB, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(b, idA, SM9KeyExchangeRole.Responder);
		byte[] ephemeralA = ExportEphemeral(initiator);
		byte[] ephemeralB = ExportEphemeral(responder);
		byte[] keyB = new byte[length];
		byte[] sB = new byte[32];
		byte[] s2 = new byte[32];
		byte[] keyA = new byte[length];
		byte[] sA = new byte[32];
		byte[] s1 = new byte[32];

		if (!responder.TryDeriveKey(ephemeralA, keyB, sB, s2) || !initiator.TryDeriveKey(ephemeralB, keyA, sA, s1))
		{
			throw new InvalidOperationException("A party failed to derive the key.");
		}

		return (keyA, keyB, sB.AsSpan().SequenceEqual(s1) && sA.AsSpan().SequenceEqual(s2));
	}
}
