using CryptoBase.SM2;
using CryptoBase.Tests.EllipticCurves;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using static CryptoBase.Tests.SM2.SM2TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SM2;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class SM2KeyExchangeTest
{
	// Known-answer vectors: the static and ephemeral keys of the initiator, with the ID "Alice", and of the responder, with "Bob", and a key of 48 bytes.
	public static IEnumerable<Func<(string Initiator, string InitiatorEphemeral, string Responder, string ResponderEphemeral, string Key)>> ExternalVectors()
	{
		yield return () => ("e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e", "6fe0bac5b09d3ab10f724638811c34464790520e4604e71e6cb0e5310623b5b1", "7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7", "d0233bdbb0b8a7bfe1aab66132ef06fc4efaedd5d5000692bc21185242a31f6f", "1ad809ebc56ddda532020c352e1e60b121ebeb7b4e632db4dd90a362cf844f8bba85140e30984ddb581199bf5a9dda22");
		yield return () => ("cb5ac204b38d0e5c9fc38a467075986754018f7dbb7cbbc5b4c78d56a88a8ad8", "1681a66c02b67fdadfc53cba9b417b9499d0159435c86bb8760c3a03ae157539", "4f54b10e0d8e9e2fe5cc79893e37fd0fd990762d1372197ed92dde464b2773ef", "a2fe43dea141e9acc88226eaba8908ad17e81376c92102cb8186e8fef61a8700", "7a103ae61a30ed9df573a5febb35a9609cbed5681bcb98a8545351bf7d6824cc4635df5203712ea506e2e3c4ec9b12e7");
		yield return () => ("ee690a34a779ab48227a2f68b062a80f92e26d82835608dd01b7452f1e4fb296", "2046c6cee085665e9f3abeba41fd38e17a26c08f2f5e8f0e1007afc0bf6a2a5d", "8ef49ea427b13cc31151e1c96ae8a48cb7919063f2d342560fb7eaaffb93d8fe", "9baf8d602e43fbae83fedb7368f98c969d378b8a647318f8cafb265296ae37de", "b18e78e5072f301399dc1f4baf2956c0ed2d5f52f19abb1705131b0865b079031259ee6c629b4faed528bcfa1c5d2cbc");
	}

	[Test]
	[MethodDataSource(nameof(ExternalVectors))]
	public async Task KeysMatchExternalVectors(string initiator, string initiatorEphemeral, string responder, string responderEphemeral, string expected)
	{
		using SM2Key a = SM2Key.ImportPrivateKey(Hex(initiator));
		using SM2Key b = SM2Key.ImportPrivateKey(Hex(responder));
		(byte[] keyA, byte[] keyB, _) = Exchange(a, "Alice"u8.ToArray(), b, "Bob"u8.ToArray(), 48, Fill(Hex(initiatorEphemeral)), Fill(Hex(responderEphemeral)));

		using (Assert.Multiple())
		{
			await Assert.That(keyA).IsEquivalentTo(Hex(expected), CollectionOrdering.Matching);
			await Assert.That(keyB).IsEquivalentTo(Hex(expected), CollectionOrdering.Matching);
		}
	}

	// A key that serves as the static key of the peer often enough builds its windows, from which the later derivations take t·P; the keys of the vectors must not change across that threshold, which both keys reach at the same exchange.
	[Test]
	[MethodDataSource(nameof(ExternalVectors))]
	public async Task KeysFromTheWindowsMatchExternalVectors(string initiator, string initiatorEphemeral, string responder, string responderEphemeral, string expected)
	{
		int threshold = TableThreshold("KeyExchangeTableThreshold");
		using SM2Key a = SM2Key.ImportPrivateKey(Hex(initiator));
		using SM2Key b = SM2Key.ImportPrivateKey(Hex(responder));
		List<string> failures = [];

		for (int i = 1; i <= threshold + 1; ++i)
		{
			(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(a, "Alice"u8.ToArray(), b, "Bob"u8.ToArray(), 48, Fill(Hex(initiatorEphemeral)), Fill(Hex(responderEphemeral)));

			if (!keyA.AsSpan().SequenceEqual(Hex(expected)) || !keyB.AsSpan().SequenceEqual(Hex(expected)) || !confirmed)
			{
				failures.Add($"exchange {i}: the keys differ from the vector");
			}

			if (HasTable(a) != i >= threshold || HasTable(b) != i >= threshold)
			{
				failures.Add($"exchange {i}: the windows are {(HasTable(a) ? "built" : "missing")} and {(HasTable(b) ? "built" : "missing")}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Both parties derive one key and confirm each other, for keys of one byte to several blocks of the KDF and IDs from empty to the longest.
	[Test]
	public async Task PartiesAgree()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		List<string> failures = [];

		foreach ((byte[] idA, byte[] idB) in ((byte[], byte[])[])[([], []), (SM2Key.DefaultId.ToArray(), "BILL456@YAHOO.COM"u8.ToArray()), (new byte[SM2Key.MaxIdLength], [0])])
		{
			foreach (int length in (int[])[1, 16, 31, 32, 33, 64, 100])
			{
				(byte[] keyA, byte[] keyB, bool confirmed) = Exchange(a, idA, b, idB, length, null, null);

				if (!keyA.AsSpan().SequenceEqual(keyB) || !confirmed)
				{
					failures.Add($"IDs of {idA.Length} and {idB.Length} bytes, a key of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The key and the confirmations hash both IDs and both static keys, in the order of the roles.
	[Test]
	public async Task MismatchesGiveOtherKeys()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		using SM2Key c = SM2Key.GenerateKey();
		byte[] idA = "ALICE123@YAHOO.COM"u8.ToArray();
		byte[] idB = "BILL456@YAHOO.COM"u8.ToArray();
		using SM2KeyExchange initiator = SM2KeyExchange.Create(a, idA, SM2KeyExchangeRole.Initiator);
		byte[] ephemeralA = ExportEphemeral(initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(b, idB, SM2KeyExchangeRole.Responder);
		byte[] ephemeralB = ExportEphemeral(responder);
		// The responder takes the ID of the initiator to be idB, and the initiator takes the static key of the responder to be c.
		byte[] keyB = Derive(responder, a, idB, ephemeralA, out byte[] sB, out _);
		byte[] keyA = Derive(initiator, c, idB, ephemeralB, out _, out byte[] s1);

		using (Assert.Multiple())
		{
			await Assert.That(keyA).IsNotEquivalentTo(keyB);
			await Assert.That(s1).IsNotEquivalentTo(sB);
		}
	}

	// GB/T 32918.3-2016, Sec. 6.1, A6 and B5: the ephemeral key of the peer must be a point on the curve, here uncompressed. The derivation then fails, writes nothing and may be tried again.
	[Test]
	public async Task InvalidEphemeralKeysFail()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		using SM2KeyExchange responder = SM2KeyExchange.Create(b, SM2Key.DefaultId, SM2KeyExchangeRole.Responder);
		using SM2KeyExchange initiator = SM2KeyExchange.Create(a, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);
		byte[] valid = ExportEphemeral(initiator);
		CurvePoint point = Curve.DecodePoint(valid);
		BigInteger p = Reference.P;
		byte[][] invalid =
		[
			[], valid.AsSpan(0, 64).ToArray(), [.. valid, 0], [0x02, .. valid.AsSpan(1, 32)], [0x03, .. valid.AsSpan(1)], [0x00, .. valid.AsSpan(1)],
			new byte[65], [0x04, .. Encode(point.X), .. Encode((point.Y + 1) % p)], [0x04, .. Encode(p), .. Encode(point.Y)], [0x04, .. Encode(point.X), .. Encode(p)],
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			byte[] key = CreateGuardedBuffer(0, 16);
			byte[] confirmation = CreateGuardedBuffer(0, 32);
			byte[] peerConfirmation = CreateGuardedBuffer(0, 32);

			if (responder.TryDeriveKey(a, SM2Key.DefaultId, encoding, key, confirmation, peerConfirmation) || ((byte[][])[key, confirmation, peerConfirmation]).Any(static output => output.AsSpan().ContainsAnyExcept(DestinationSentinel)))
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(responder.TryDeriveKey(a, SM2Key.DefaultId, valid, new byte[16])).IsTrue();
		}
	}

	// A7 and B6 fail where the shared point is the point at infinity: P + x̄·R of the peer is, for a static key of the peer that the reference picks as −x̄·r, or t = d + x̄·r of the party is 0, for a static key of the party picked as −x̄·r. Each derivation runs until the key of the peer has built its windows, which the later ones take.
	[Test]
	public async Task SharedPointsAtInfinityFail()
	{
		int threshold = TableThreshold("KeyExchangeTableThreshold");
		BigInteger r = Integer("D4DE1547 4DB74D06 491C440D 305E0124 00990F3E 390C7E87 153C12DB 2EA60BB3");
		CurvePoint ephemeral = Reference.PublicKey(r);
		BigInteger cancelling = (N - Truncate(ephemeral.X) * r % N) % N;
		using SM2Key own = SM2Key.GenerateKey();
		using SM2Key peer = SM2Key.ImportPrivateKey(Encode(cancelling));
		using SM2Key ownCancelling = SM2Key.ImportPrivateKey(Encode(cancelling));
		using SM2Key other = SM2Key.GenerateKey();
		List<string> failures = [];

		for (int i = 1; i <= threshold + 1; ++i)
		{
			// The peer has static key −x̄·r and the ephemeral key r, so P + x̄·R = O.
			using SM2KeyExchange party = SM2KeyExchange.Create(own, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);

			if (party.TryDeriveKey(peer, SM2Key.DefaultId, EncodePoint(ephemeral), new byte[16]))
			{
				failures.Add($"derivation {i}: P + x̄·R = O gave a key");
			}

			// The party has static key −x̄·r and the ephemeral key r, so t = 0.
			using SM2KeyExchange zero = SM2KeyExchange.Create(ownCancelling, SM2Key.DefaultId, SM2KeyExchangeRole.Responder, Fill(Encode(r)));
			using SM2KeyExchange otherParty = SM2KeyExchange.Create(other, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);

			if (zero.TryDeriveKey(other, SM2Key.DefaultId, ExportEphemeral(otherParty), new byte[16]))
			{
				failures.Add($"derivation {i}: t = 0 gave a key");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(HasTable(peer) && HasTable(other)).IsTrue();
		}
	}

	// P + x̄·R = 2P for a static key of the peer that the reference picks as x̄·r, where t·P and (t·x̄)·R are equal points, which the products from the windows of P and those of k·P + l·Q without them add; the key of the initiator must be that of the reference before and after the windows.
	[Test]
	public async Task SharedPointsOfEqualTermsMatchTheReference()
	{
		int threshold = TableThreshold("KeyExchangeTableThreshold");
		Random random = new(7);
		BigInteger r = Integer("D4DE1547 4DB74D06 491C440D 305E0124 00990F3E 390C7E87 153C12DB 2EA60BB3");
		CurvePoint ephemeral = Reference.PublicKey(r);
		BigInteger d = Truncate(ephemeral.X) * r % N;
		BigInteger ownKey = ECReference.RandomBelow(random, N - 2) + 1;
		using SM2Key own = SM2Key.ImportPrivateKey(Encode(ownKey));
		using SM2Key peer = SM2Key.ImportPrivateKey(Encode(d));
		List<string> failures = [];

		for (int i = 1; i <= threshold + 1; ++i)
		{
			BigInteger ownEphemeral = ECReference.RandomBelow(random, N - 1) + 1;
			using SM2KeyExchange party = SM2KeyExchange.Create(own, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator, Fill(Encode(ownEphemeral)));
			byte[] key = new byte[16];

			if (!party.TryDeriveKey(peer, SM2Key.DefaultId, EncodePoint(ephemeral), key) || !key.AsSpan().SequenceEqual(ReferenceInitiatorKey(ownKey, ownEphemeral, SM2Key.DefaultId, Reference.PublicKey(d), ephemeral, SM2Key.DefaultId, key.Length)))
			{
				failures.Add($"derivation {i}: the key differs from the reference");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(HasTable(peer)).IsTrue();
		}
	}

	// A successful derivation erases the secret of the instance, so an ephemeral key serves one exchange.
	[Test]
	public async Task InstancesDeriveOnce()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		using SM2KeyExchange initiator = SM2KeyExchange.Create(a, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(b, SM2Key.DefaultId, SM2KeyExchangeRole.Responder);
		byte[] ephemeralB = ExportEphemeral(responder);

		using (Assert.Multiple())
		{
			await Assert.That(initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeralB, new byte[16])).IsTrue();
			await Assert.That(() => initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeralB, new byte[16])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(ExportEphemeral(initiator).Length).IsEqualTo(65);
		}
	}

	[Test]
	public async Task ArgumentsAreChecked()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		using SM2Key publicOnly = SM2Key.ImportPublicKey(ExportPublicKey(a));
		SM2Key disposed = SM2Key.GenerateKey();
		disposed.Dispose();
		using SM2KeyExchange initiator = SM2KeyExchange.Create(a, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(b, SM2Key.DefaultId, SM2KeyExchangeRole.Responder);
		byte[] ephemeral = ExportEphemeral(responder);
		byte[] buffer = new byte[64];

		using (Assert.Multiple())
		{
			await Assert.That(() => SM2KeyExchange.Create(null!, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => SM2KeyExchange.Create(publicOnly, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => SM2KeyExchange.Create(disposed, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => SM2KeyExchange.Create(a, new byte[SM2Key.MaxIdLength + 1], SM2KeyExchangeRole.Initiator)).Throws<ArgumentException>().WithParameterName("id");
			await Assert.That(() => SM2KeyExchange.Create(a, SM2Key.DefaultId, (SM2KeyExchangeRole)2)).Throws<ArgumentOutOfRangeException>().WithParameterName("role");
			await Assert.That(() => initiator.TryDeriveKey(null!, SM2Key.DefaultId, ephemeral, new byte[16])).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => initiator.TryDeriveKey(disposed, SM2Key.DefaultId, ephemeral, new byte[16])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => initiator.TryDeriveKey(b, new byte[SM2Key.MaxIdLength + 1], ephemeral, new byte[16])).Throws<ArgumentException>().WithParameterName("peerId");
			await Assert.That(() => initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeral, [])).Throws<ArgumentOutOfRangeException>().WithParameterName("sharedKey");
			await Assert.That(() => initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeral, new byte[16], new byte[31], new byte[32])).Throws<ArgumentException>().WithParameterName("confirmation");
			await Assert.That(() => initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeral, new byte[16], new byte[32], new byte[31])).Throws<ArgumentException>().WithParameterName("peerConfirmation");
			await Assert.That(() => initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeral, buffer.AsSpan(0, 16), buffer.AsSpan(8, 32), new byte[32])).Throws<ArgumentException>();
			await Assert.That(() => initiator.TryDeriveKey(b, SM2Key.DefaultId, ephemeral, new byte[16], buffer.AsSpan(0, 32), buffer.AsSpan(31, 32))).Throws<ArgumentException>();
			await Assert.That(() => initiator.ExportEphemeralPublicKey(new byte[64])).Throws<ArgumentException>().WithParameterName("destination");
		}
	}

	// The inputs are read before any output is written, so they may share a buffer with the outputs: here the ephemeral key of the peer lies under the key, and its ID under the confirmation.
	[Test]
	public async Task InputsMayOverlapTheOutputs()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		using SM2KeyExchange initiator = SM2KeyExchange.Create(a, "Alice"u8, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(b, "Bob"u8, SM2KeyExchangeRole.Responder);
		byte[] ephemeralA = ExportEphemeral(initiator);
		byte[] ephemeralB = ExportEphemeral(responder);
		byte[] keyB = new byte[64];
		byte[] sB = new byte[32];
		byte[] s2 = new byte[32];
		bool derivedB = responder.TryDeriveKey(a, "Alice"u8, ephemeralA, keyB, sB, s2);
		byte[] buffer = [.. ephemeralB, .. "Bob"u8, .. new byte[60]];
		bool derivedA = initiator.TryDeriveKey(b, buffer.AsSpan(65, 3), buffer.AsSpan(0, 65), buffer.AsSpan(0, 64), buffer.AsSpan(64, 32), buffer.AsSpan(96, 32));

		using (Assert.Multiple())
		{
			await Assert.That(derivedB).IsTrue();
			await Assert.That(derivedA).IsTrue();
			await Assert.That(buffer.AsSpan(0, 64).ToArray()).IsEquivalentTo(keyB, CollectionOrdering.Matching);
			await Assert.That(buffer.AsSpan(64, 32).ToArray()).IsEquivalentTo(s2, CollectionOrdering.Matching);
			await Assert.That(buffer.AsSpan(96, 32).ToArray()).IsEquivalentTo(sB, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task DisposedInstancesThrow()
	{
		using SM2Key a = SM2Key.GenerateKey();
		using SM2Key b = SM2Key.GenerateKey();
		SM2KeyExchange exchange = SM2KeyExchange.Create(a, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator);
		byte[] ephemeral = ExportEphemeral(exchange);
		exchange.Dispose();
		exchange.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => exchange.ExportEphemeralPublicKey(new byte[65])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => exchange.TryDeriveKey(b, SM2Key.DefaultId, ephemeral, new byte[16])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// The keys of both parties and whether each confirmation matches the one its peer expects, with ephemeral keys from fillA and fillB, or fresh ones.
	private static (byte[] KeyA, byte[] KeyB, bool Confirmed) Exchange(SM2Key a, byte[] idA, SM2Key b, byte[] idB, int length, Action<Span<byte>>? fillA, Action<Span<byte>>? fillB)
	{
		using SM2KeyExchange initiator = fillA is null ? SM2KeyExchange.Create(a, idA, SM2KeyExchangeRole.Initiator) : SM2KeyExchange.Create(a, idA, SM2KeyExchangeRole.Initiator, fillA);
		using SM2KeyExchange responder = fillB is null ? SM2KeyExchange.Create(b, idB, SM2KeyExchangeRole.Responder) : SM2KeyExchange.Create(b, idB, SM2KeyExchangeRole.Responder, fillB);
		byte[] ephemeralA = ExportEphemeral(initiator);
		byte[] ephemeralB = ExportEphemeral(responder);
		byte[] keyB = new byte[length];
		byte[] sB = new byte[32];
		byte[] s2 = new byte[32];
		byte[] keyA = new byte[length];
		byte[] sA = new byte[32];
		byte[] s1 = new byte[32];

		if (!responder.TryDeriveKey(a, idA, ephemeralA, keyB, sB, s2) || !initiator.TryDeriveKey(b, idB, ephemeralB, keyA, sA, s1))
		{
			throw new InvalidOperationException("A party failed to derive the key.");
		}

		return (keyA, keyB, sB.AsSpan().SequenceEqual(s1) && sA.AsSpan().SequenceEqual(s2));
	}

	private static byte[] Derive(SM2KeyExchange exchange, SM2Key peer, byte[] peerId, byte[] peerEphemeral, out byte[] confirmation, out byte[] peerConfirmation)
	{
		byte[] key = new byte[16];
		confirmation = new byte[32];
		peerConfirmation = new byte[32];

		if (!exchange.TryDeriveKey(peer, peerId, peerEphemeral, key, confirmation, peerConfirmation))
		{
			throw new InvalidOperationException("The derivation failed.");
		}

		return key;
	}

	// The key of the initiator with the static key d and the ephemeral key r, from the static key and the ephemeral key of the responder, by the reference: U = t·(P + x̄·R) for t = (d + x̄·r) mod n, and K = KDF(x_U ‖ y_U ‖ Z_A ‖ Z_B).
	private static byte[] ReferenceInitiatorKey(BigInteger d, BigInteger r, ReadOnlySpan<byte> idA, CurvePoint responderKey, CurvePoint responderEphemeral, ReadOnlySpan<byte> idB, int length)
	{
		BigInteger t = (d + Truncate(Reference.PublicKey(r).X) * r) % N;
		CurvePoint u = Reference.Multiply(Reference.Add(responderKey, Reference.Multiply(responderEphemeral, Truncate(responderEphemeral.X))), t) ?? throw new InvalidOperationException("The shared point is the point at infinity.");
		return ReferenceKdf([.. Encode(u.X), .. Encode(u.Y), .. ReferenceZ(idA, Reference.PublicKey(d)), .. ReferenceZ(idB, responderKey)], length);
	}

	// x̄ = 2^127 + (x mod 2^127).
	private static BigInteger Truncate(BigInteger x)
	{
		return (BigInteger.One << 127) + (x & (BigInteger.One << 127) - 1);
	}

	private static byte[] ExportEphemeral(SM2KeyExchange exchange)
	{
		byte[] ephemeral = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
		exchange.ExportEphemeralPublicKey(ephemeral);
		return ephemeral;
	}

	private static byte[] ExportPublicKey(SM2Key key)
	{
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}
}
