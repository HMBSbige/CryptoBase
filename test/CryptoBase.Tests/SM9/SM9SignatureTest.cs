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
public class SM9SignatureTest
{
	private static readonly byte[][] Ids = [[], "Alice"u8.ToArray(), [0x00], [.. Enumerable.Range(0, 1000).Select(static i => (byte)i)]];

	// IDs from empty to long and messages around the SM3 block, as h ‖ S and in DER, verified by the master key that extracted the keys and by its public key alone.
	[Test]
	public async Task SignaturesVerify()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(master));
		List<string> failures = [];

		foreach (byte[] id in Ids)
		{
			using SM9SignatureKey key = master.ExtractKey(id);

			foreach (int length in (int[])[0, 1, 55, 56, 63, 64, 1000])
			{
				byte[] message = [.. Enumerable.Range(0, length).Select(static i => (byte)(i * 7))];
				byte[] signature = Sign(key, message);
				byte[] der = SignDer(key, message);

				if (!master.Verify(message, signature, id) || !verifier.Verify(message, signature, id) || !verifier.VerifyDer(message, der, id) || der.Length is not 104 || der[0] is not 0x30)
				{
					failures.Add($"ID of {id.Length} bytes, message of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The steps of GM/T 0044.2-2016, Sec. 5.3 and 7.1, from the BigInteger reference for H1, H2 and the groups and from the pairing and powers of the mathematics, which their own tests check against the reference: dsA = [ks/(H1(ID ‖ 01, N) + ks)]P1, P = [H1(ID ‖ 01, N)]P2 + Ppub-s and H2(M ‖ e(S, P)·g^h, N) = h for g = e(P1, Ppub-s).
	[Test]
	public async Task SignaturesFollowTheSteps()
	{
		Random random = new(3);
		BigInteger ks = RandomScalar(random);
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.ImportPrivateKey(Encode(ks));
		byte[] id = "bob@example.com"u8.ToArray();
		using SM9SignatureKey key = master.ExtractKey(id);
		byte[] message = "a message to sign"u8.ToArray();
		byte[] signature = Sign(key, message);
		BigInteger h = new(signature.AsSpan(0, 32), true, true);
		G1Value s = new(new BigInteger(signature.AsSpan(33, 32), true, true), new BigInteger(signature.AsSpan(65, 32), true, true));
		BigInteger h1 = ReferenceHash(0x01, [.. id, 0x01]);
		G2Value publicKey = Multiply(P2, ks)!;
		G2Value p = Add(Multiply(P2, h1), publicKey)!;
		SM9Pairing.Pair(SM9EllipticCurveTestUtils.Element(s), SM9EllipticCurveTestUtils.Element(p), out SM9Fp12 u);
		SM9Pairing.Pair(in SM9G1.Generator, SM9EllipticCurveTestUtils.Element(publicKey), out SM9Fp12 g);
		SM9GT.Power(in g, SM9EllipticCurveTestUtils.Scalar(h), out SM9Fp12 t);
		SM9Fp12.Multiply(in u, in t, out SM9Fp12 w);
		byte[] encoded = new byte[SM9GT.EncodedLength];
		SM9GT.Encode(in w, encoded);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(EncodePoint(Multiply(P1, ks * ECReference.Inverse((h1 + ks) % N, N) % N)!), CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(master)).IsEquivalentTo(EncodePoint(publicKey), CollectionOrdering.Matching);
			await Assert.That(ReferenceHash(0x02, [.. message, .. encoded])).IsEqualTo(h);
		}
	}

	// With empty additional data the random number r follows from dsA and the message alone; other inputs change it. The signatures before and after the key builds the tables of its products agree.
	[Test]
	public async Task SigningIsDeterministicWithoutAdditionalData()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		byte[] message = "message"u8.ToArray();
		byte[] first = SignWith(key, message, []);
		bool same = true;

		for (int i = 0; i < 32; ++i)
		{
			same &= SignWith(key, message, []).AsSpan().SequenceEqual(first);
		}

		using (Assert.Multiple())
		{
			await Assert.That(same).IsTrue();
			await Assert.That(SignWith(key, message, [])).IsEquivalentTo(first, CollectionOrdering.Matching);
			await Assert.That(SignWith(key, message, [1])).IsNotEquivalentTo(first);
			await Assert.That(SignWith(key, "messagE"u8.ToArray(), [])).IsNotEquivalentTo(first);
			await Assert.That(Sign(key, message)).IsNotEquivalentTo(Sign(key, message));
			await Assert.That(master.Verify(message, first, "Alice"u8)).IsTrue();
		}
	}

	// The signing key of GM/T 0044.5, A.2, signs the message of the example with empty additional data into a known h ‖ S for the nonces of SM3Nonce and the g of the example.
	[Test]
	public async Task SignatureWithoutAdditionalDataMatches()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.ImportPrivateKey(Scalar(SM9Vectors.SignMasterKey));
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		byte[] message = "Chinese IBS standard"u8.ToArray();
		byte[] expected = Hex("875EC2D90F2CC668833407BB1630EBFED8D98A635409E7B5E6664A53C8EDFD95 04 914FFB0A96E76231EB0F6CDF026645E1EA7050020241F33303103FE4150E18F6 40FCBD631B02861548D5B3D8181EB7AD82B28F02942EC8DF2C66DCA789C21B60");

		using (Assert.Multiple())
		{
			await Assert.That(SignWith(key, message, [])).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(master.Verify(message, expected, "Alice"u8)).IsTrue();
		}
	}

	[Test]
	public async Task OtherIdsKeysAndMessagesFail()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureMasterKey other = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		using SM9SignatureKey otherKey = other.ExtractKey("Alice"u8);
		byte[] message = "message"u8.ToArray();
		byte[] signature = Sign(key, message);

		using (Assert.Multiple())
		{
			await Assert.That(master.Verify(message, signature, "Alice"u8)).IsTrue();
			await Assert.That(master.Verify(message, signature, "Alicf"u8)).IsFalse();
			await Assert.That(master.Verify(message, signature, "Alice\0"u8)).IsFalse();
			await Assert.That(master.Verify(message, signature, [])).IsFalse();
			await Assert.That(other.Verify(message, signature, "Alice"u8)).IsFalse();
			await Assert.That(master.Verify(message, Sign(otherKey, message), "Alice"u8)).IsFalse();
			await Assert.That(master.Verify("messagE"u8, signature, "Alice"u8)).IsFalse();
			await Assert.That(master.Verify([.. message, 0], signature, "Alice"u8)).IsFalse();
		}
	}

	// GM/T 0044.2-2016, Sec. 7.1, B1 and B2: h in [1, N − 1] and S a point on the curve, uncompressed; any changed byte fails, as does any other length.
	[Test]
	public async Task InvalidSignaturesFail()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		byte[] message = "message"u8.ToArray();
		byte[] signature = Sign(key, message);
		BigInteger y = new(signature.AsSpan(65, 32), true, true);
		byte[] s = signature.AsSpan(32).ToArray();
		byte[][] invalid =
		[
			[], signature.AsSpan(0, 96).ToArray(), [.. signature, 0], [.. Encode(0), .. s], [.. Encode(N), .. s], [.. Encode(N + 1), .. s], [.. Encode((BigInteger.One << 256) - 1), .. s],
			[.. signature.AsSpan(0, 32), 0x02, .. s.AsSpan(1, 32)], [.. signature.AsSpan(0, 32), 0x00, .. s.AsSpan(1)], [.. signature.AsSpan(0, 32), 0x06, .. s.AsSpan(1)],
			[.. signature.AsSpan(0, 32), .. new byte[65]], [.. signature.AsSpan(0, 32), 0x04, .. new byte[64]], [.. signature.AsSpan(0, 65), .. Encode((y + 1) % P)],
			[.. signature.AsSpan(0, 33), .. Encode(P), .. signature.AsSpan(65)], [.. signature.AsSpan(0, 65), .. Encode(P)],
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			if (master.Verify(message, encoding, "Alice"u8))
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		for (int i = 0; i < signature.Length; ++i)
		{
			if (master.Verify(message, Flip(signature, i), "Alice"u8))
			{
				failures.Add($"byte {i} flipped");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(master.Verify(message, signature, "Alice"u8)).IsTrue();
		}
	}

	// The SM9Signature of GB/T 41389-2022 in DER, its only encoding: any other length form, tag, unused bit count, H length or trailing byte fails.
	[Test]
	public async Task NonDerSignaturesFail()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		byte[] message = "message"u8.ToArray();
		byte[] der = SignDer(key, message);
		byte[] h = der.AsSpan(4, 32).ToArray();
		byte[] s = der.AsSpan(39).ToArray();
		byte[][] invalid =
		[
			[], [.. der, 0], der.AsSpan(0, 103).ToArray(), Sign(key, message),
			[0x30, 0x81, 0x66, .. der.AsSpan(2)], [0x31, .. der.AsSpan(1)], [0x30, 0x66, 0x04, 0x81, 0x20, .. h, .. der.AsSpan(36)],
			[.. der.AsSpan(0, 36), 0x03, 0x42, 0x01, .. s], [.. der.AsSpan(0, 36), 0x04, 0x41, .. s], [.. der.AsSpan(0, 36), 0x23, 0x42, 0x00, .. s],
			[0x30, 0x67, 0x04, 0x21, 0x00, .. h, .. der.AsSpan(36)], [0x30, 0x65, 0x04, 0x1F, .. h.AsSpan(1), .. der.AsSpan(36)],
			[0x30, 0x80, .. der.AsSpan(2), 0x00, 0x00], [0x30, 0x66, 0x24, 0x20, .. h, .. der.AsSpan(36)],
		];
		List<string> failures = [];

		foreach (byte[] encoding in invalid)
		{
			if (master.VerifyDer(message, encoding, "Alice"u8))
			{
				failures.Add(Convert.ToHexString(encoding));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(master.VerifyDer(message, der, "Alice"u8)).IsTrue();
			await Assert.That(master.Verify(message, [.. h, .. s], "Alice"u8)).IsTrue();
		}
	}

	// An exported key imports with its master public key and ID, and the import checks that it is that of the ID under the master key.
	[Test]
	public async Task PrivateKeysImportForTheirIdAlone()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureMasterKey other = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		byte[] privateKey = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(master);
		using SM9SignatureKey imported = SM9SignatureKey.ImportPrivateKey(privateKey, publicKey, "Alice"u8);
		byte[] message = "message"u8.ToArray();
		BigInteger x = new(privateKey.AsSpan(1, 32), true, true);
		BigInteger y = new(privateKey.AsSpan(33, 32), true, true);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(master.Verify(message, Sign(imported, message), "Alice"u8)).IsTrue();
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(privateKey, publicKey, "Bob"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(privateKey, ExportPublicKey(other), "Alice"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(privateKey.AsSpan(0, 64), publicKey, "Alice"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey([0x04, .. Encode(x), .. Encode((y + 1) % P)], publicKey, "Alice"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey([0x02, .. privateKey.AsSpan(1)], publicKey, "Alice"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(privateKey, publicKey.AsSpan(1), "Alice"u8)).Throws<ArgumentException>().WithParameterName("masterPublicKey");
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(privateKey, EncodeTwistPointOutsideG2(), "Alice"u8)).Throws<ArgumentException>().WithParameterName("masterPublicKey");
		}
	}

	// For any hid, the keys are those of GM/T 0044.2, Sec. 5.3, and import with that hid, and the master key and its public key with that hid verify their signatures, h ‖ S and in DER; with another hid, verification fails and the import throws.
	[Test]
	public async Task OtherHidsSignAndVerify()
	{
		Random random = new(7);
		byte[] id = "Alice"u8.ToArray();
		byte[] message = "message"u8.ToArray();
		List<string> failures = [];

		foreach (byte hid in (byte[])[0x00, 0x02, 0x05, 0x80, 0xFF])
		{
			BigInteger ks = RandomScalar(random);
			using SM9SignatureMasterKey master = SM9SignatureMasterKey.ImportPrivateKey(Encode(ks), hid);
			byte[] publicKey = ExportPublicKey(master);
			using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(publicKey, hid);
			using SM9SignatureMasterKey other = SM9SignatureMasterKey.ImportPublicKey(publicKey, (byte)(hid ^ 1));
			using SM9SignatureKey key = master.ExtractKey(id);
			byte[] privateKey = ExportPrivateKey(key);
			BigInteger h1 = ReferenceHash(0x01, [.. id, hid]);
			using SM9SignatureKey imported = SM9SignatureKey.ImportPrivateKey(privateKey, publicKey, id, hid);
			byte[] signature = Sign(imported, message);
			byte[] der = SignDer(key, message);

			if (!privateKey.AsSpan().SequenceEqual(EncodePoint(Multiply(P1, ks * ECReference.Inverse((h1 + ks) % N, N) % N)!))
				|| master.Hid != hid || verifier.Hid != hid
				|| !master.Verify(message, signature, id) || !verifier.Verify(message, signature, id) || !verifier.VerifyDer(message, der, id)
				|| other.Verify(message, signature, id) || other.VerifyDer(message, der, id)
				|| !ImportThrows(() => SM9SignatureKey.ImportPrivateKey(privateKey, publicKey, id, (byte)(hid ^ 1))))
			{
				failures.Add($"hid {hid:X2}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The default hid is 0x01 and leaves the master public key unchanged: the signatures of a key of another hid do not verify with a default verifier, and the key does not import by default.
	[Test]
	public async Task HidIsOneByDefault()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		byte[] privateKey = new byte[32];
		master.ExportPrivateKey(privateKey);
		using SM9SignatureMasterKey imported = SM9SignatureMasterKey.ImportPrivateKey(privateKey);
		using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(master));
		using SM9SignatureMasterKey other = SM9SignatureMasterKey.ImportPrivateKey(privateKey, 0x05);
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);
		using SM9SignatureKey otherKey = other.ExtractKey("Alice"u8);
		byte[] message = "message"u8.ToArray();

		using (Assert.Multiple())
		{
			await Assert.That(master.Hid).IsEqualTo((byte)0x01);
			await Assert.That(imported.Hid).IsEqualTo((byte)0x01);
			await Assert.That(verifier.Hid).IsEqualTo((byte)0x01);
			await Assert.That(other.Hid).IsEqualTo((byte)0x05);
			await Assert.That(ExportPublicKey(other)).IsEquivalentTo(ExportPublicKey(master), CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(otherKey)).IsNotEquivalentTo(ExportPrivateKey(key));
			await Assert.That(verifier.Verify(message, Sign(key, message), "Alice"u8)).IsTrue();
			await Assert.That(verifier.Verify(message, Sign(otherKey, message), "Alice"u8)).IsFalse();
			await Assert.That(other.Verify(message, Sign(otherKey, message), "Alice"u8)).IsTrue();
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(ExportPrivateKey(otherKey), ExportPublicKey(master), "Alice"u8)).Throws<ArgumentException>().WithParameterName("privateKey");
		}
	}

	// The first signature and verification of an instance compute g and go without its table, and the later ones take it, on several threads at once.
	[Test]
	public async Task OneInstanceSignsAndVerifiesConcurrently()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		byte[] publicKey = ExportPublicKey(master);
		byte[][] messages = [.. Enumerable.Range(0, 32).Select(static i => BitConverter.GetBytes(i))];

		for (int round = 0; round < 3; ++round)
		{
			using SM9SignatureKey signer = master.ExtractKey("Alice"u8);
			using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(publicKey);
			bool[] valid = new bool[messages.Length];
			Parallel.For(0, messages.Length, i =>
			{
				byte[] signature = Sign(signer, messages[i]);
				valid[i] = verifier.Verify(messages[i], signature, "Alice"u8) && !verifier.Verify(messages[(i + 1) % messages.Length], signature, "Alice"u8);
			});

			await Assert.That(valid).All(static value => value);
		}
	}

	[Test]
	public async Task ArgumentsAreChecked()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		using SM9SignatureKey key = master.ExtractKey("Alice"u8);

		using (Assert.Multiple())
		{
			await Assert.That(SM9SignatureKey.SignatureLength).IsEqualTo(97);
			await Assert.That(SM9SignatureKey.DerSignatureLength).IsEqualTo(104);
			await Assert.That(SM9SignatureKey.PrivateKeyLength).IsEqualTo(65);
			await Assert.That(() => key.Sign([], new byte[96])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.SignDer([], new byte[103])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.ExportPrivateKey(new byte[64])).Throws<ArgumentException>().WithParameterName("destination");
		}
	}

	// Disposal erases dsA and the table of its products, which the signatures before it have built, and the instance throws from then on.
	[Test]
	public async Task DisposedKeysThrow()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		SM9SignatureKey key = master.ExtractKey("Alice"u8);
		object privateKey = typeof(SM9SignatureKey).GetField("_privateKey", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(key)!;
		FieldInfo tableField = typeof(SM9G1FixedBase).GetField("_table", BindingFlags.NonPublic | BindingFlags.Instance)!;

		while (tableField.GetValue(privateKey) is null)
		{
			_ = Sign(key, [1]);
		}

		SM9BaseTable<SM9Fp> table = (SM9BaseTable<SM9Fp>)tableField.GetValue(privateKey)!;
		bool filled = !table.Entries.ToArray().All(static entry => IsZero(in entry));
		key.Dispose();
		key.Dispose();
		SM9AffinePoint<SM9Fp> stored = (SM9AffinePoint<SM9Fp>)typeof(SM9G1FixedBase).GetField("_point", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(privateKey)!;

		using (Assert.Multiple())
		{
			await Assert.That(filled).IsTrue();
			await Assert.That(IsZero(in stored)).IsTrue();
			await Assert.That(table.Entries.ToArray().All(static entry => IsZero(in entry))).IsTrue();
			await Assert.That(tableField.GetValue(privateKey)).IsNull();
			await Assert.That(() => key.Sign([], new byte[97])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.SignDer([], new byte[104])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPrivateKey(new byte[65])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	private static byte[] SignWith(SM9SignatureKey key, byte[] message, byte[] additionalData)
	{
		byte[] signature = new byte[SM9SignatureKey.SignatureLength];
		_ = key.Sign(message, additionalData, signature, false);
		return signature;
	}
}
