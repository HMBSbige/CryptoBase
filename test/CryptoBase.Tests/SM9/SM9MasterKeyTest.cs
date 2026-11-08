using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.SM9;
using CryptoBase.Tests.EllipticCurves.SM9;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.SM9.SM9TestUtils;

namespace CryptoBase.Tests.SM9;

// Assert.That runs its delegates at the await, so they read the keys before they are disposed.
// ReSharper disable AccessToDisposedClosure
public class SM9MasterKeyTest
{
	// The master private keys lie in [1, N − 1], the public keys follow from them, and the exports import again.
	[Test]
	public async Task MasterKeysRoundTrip()
	{
		List<string> failures = [];

		foreach (BigInteger value in (BigInteger[])[1, 2, N - 1, RandomScalar(new Random(5))])
		{
			using SM9SignatureMasterKey sign = SM9SignatureMasterKey.ImportPrivateKey(Encode(value));
			using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.ImportPrivateKey(Encode(value));
			byte[] signPrivate = new byte[32];
			byte[] encryptPrivate = new byte[32];
			sign.ExportPrivateKey(signPrivate);
			encrypt.ExportPrivateKey(encryptPrivate);
			using SM9SignatureMasterKey signPublic = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(sign));
			using SM9EncryptionMasterKey encryptPublic = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(encrypt));

			if (!signPrivate.AsSpan().SequenceEqual(Encode(value)) || !encryptPrivate.AsSpan().SequenceEqual(Encode(value))
				|| !ExportPublicKey(sign).AsSpan().SequenceEqual(EncodePoint(Multiply(P2, value)!)) || !ExportPublicKey(encrypt).AsSpan().SequenceEqual(EncodePoint(Multiply(P1, value)!))
				|| !ExportPublicKey(signPublic).AsSpan().SequenceEqual(ExportPublicKey(sign)) || !ExportPublicKey(encryptPublic).AsSpan().SequenceEqual(ExportPublicKey(encrypt))
				|| !sign.HasPrivateKey || !encrypt.HasPrivateKey || signPublic.HasPrivateKey || encryptPublic.HasPrivateKey)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task PrivateKeysOutsideTheRangeThrow()
	{
		List<string> failures = [];

		foreach (byte[] encoded in (byte[][])[Encode(0), Encode(N), Encode(N + 1), Encode((BigInteger.One << 256) - 1), new byte[31], new byte[33]])
		{
			if (!Throws(() => SM9SignatureMasterKey.ImportPrivateKey(encoded)) || !Throws(() => SM9EncryptionMasterKey.ImportPrivateKey(encoded)))
			{
				failures.Add(Convert.ToHexString(encoded));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A signature master public key lies in G2 and an encryption one on the curve, uncompressed.
	[Test]
	public async Task InvalidPublicKeysThrow()
	{
		using SM9SignatureMasterKey sign = SM9SignatureMasterKey.GenerateKey();
		using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.GenerateKey();
		byte[] g2 = ExportPublicKey(sign);
		byte[] g1 = ExportPublicKey(encrypt);
		G1Value point = new(new BigInteger(g1.AsSpan(1, 32), true, true), new BigInteger(g1.AsSpan(33, 32), true, true));
		byte[][] invalidG2 = [[], g2.AsSpan(1).ToArray(), [.. g2, 0], [0x02, .. g2.AsSpan(1, 64)], [0x00, .. g2.AsSpan(1)], new byte[129], [0x04, .. new byte[128]], [.. g2.AsSpan(0, 128), (byte)(g2[128] ^ 1)], EncodeTwistPointOutsideG2(), [0x04, .. Encode(P), .. g2.AsSpan(33)]];
		byte[][] invalidG1 = [[], g1.AsSpan(1).ToArray(), [.. g1, 0], [0x02, .. g1.AsSpan(1, 32)], [0x03, .. g1.AsSpan(1)], [0x04, .. new byte[64]], [0x04, .. Encode(point.X), .. Encode((point.Y + 1) % P)], [0x04, .. Encode(P), .. Encode(point.Y)], [0x04, .. Encode(point.X), .. Encode(P)]];
		List<string> failures = [];

		foreach (byte[] encoded in invalidG2)
		{
			if (!Throws(() => SM9SignatureMasterKey.ImportPublicKey(encoded)))
			{
				failures.Add($"G2 {Convert.ToHexString(encoded)}");
			}
		}

		foreach (byte[] encoded in invalidG1)
		{
			if (!Throws(() => SM9EncryptionMasterKey.ImportPublicKey(encoded)))
			{
				failures.Add($"G1 {Convert.ToHexString(encoded)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// GenerateKey draws again for 0 and the values from N on, and keeps the hid.
	[Test]
	public async Task GenerateKeyDrawsAgainOutsideTheRange()
	{
		BigInteger expected = N - 1;
		using SM9SignatureMasterKey sign = SM9SignatureMasterKey.GenerateKey(Fill(Encode(0), Encode(N), Encode((BigInteger.One << 256) - 1), Encode(expected)), 0x07);
		using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.GenerateKey(Fill(Encode(N + 5), Encode(expected)), 0x08);
		byte[] signPrivate = new byte[32];
		byte[] encryptPrivate = new byte[32];
		sign.ExportPrivateKey(signPrivate);
		encrypt.ExportPrivateKey(encryptPrivate);

		using (Assert.Multiple())
		{
			await Assert.That(signPrivate).IsEquivalentTo(Encode(expected), CollectionOrdering.Matching);
			await Assert.That(encryptPrivate).IsEquivalentTo(Encode(expected), CollectionOrdering.Matching);
			await Assert.That(sign.Hid).IsEqualTo((byte)0x07);
			await Assert.That(encrypt.Hid).IsEqualTo((byte)0x08);
		}
	}

	// The master keys take every hid, which they report, and 0x01 for signatures and 0x03 for encryption by default; the hid changes neither master public key.
	[Test]
	public async Task MasterKeysKeepTheirHid()
	{
		byte[] privateKey = Encode(RandomScalar(new Random(9)));
		using SM9SignatureMasterKey sign = SM9SignatureMasterKey.ImportPrivateKey(privateKey);
		using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.ImportPrivateKey(privateKey);
		using SM9SignatureMasterKey generatedSign = SM9SignatureMasterKey.GenerateKey();
		using SM9EncryptionMasterKey generatedEncrypt = SM9EncryptionMasterKey.GenerateKey();
		using SM9SignatureMasterKey publicSign = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(sign));
		using SM9EncryptionMasterKey publicEncrypt = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(encrypt));
		using SM9SignatureMasterKey chosenSign = SM9SignatureMasterKey.GenerateKey(0x00);
		using SM9EncryptionMasterKey chosenEncrypt = SM9EncryptionMasterKey.GenerateKey(0xFF);
		List<string> failures = [];

		for (int hid = 0; hid <= 0xFF; ++hid)
		{
			using SM9SignatureMasterKey signWith = SM9SignatureMasterKey.ImportPrivateKey(privateKey, (byte)hid);
			using SM9EncryptionMasterKey encryptWith = SM9EncryptionMasterKey.ImportPrivateKey(privateKey, (byte)hid);
			using SM9SignatureMasterKey signPublic = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(sign), (byte)hid);
			using SM9EncryptionMasterKey encryptPublic = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(encrypt), (byte)hid);

			if (signWith.Hid != hid || encryptWith.Hid != hid || signPublic.Hid != hid || encryptPublic.Hid != hid
				|| !ExportPublicKey(signWith).AsSpan().SequenceEqual(ExportPublicKey(sign)) || !ExportPublicKey(encryptWith).AsSpan().SequenceEqual(ExportPublicKey(encrypt)))
			{
				failures.Add($"{hid:X2}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(sign.Hid).IsEqualTo((byte)0x01);
			await Assert.That(generatedSign.Hid).IsEqualTo((byte)0x01);
			await Assert.That(publicSign.Hid).IsEqualTo((byte)0x01);
			await Assert.That(encrypt.Hid).IsEqualTo((byte)0x03);
			await Assert.That(generatedEncrypt.Hid).IsEqualTo((byte)0x03);
			await Assert.That(publicEncrypt.Hid).IsEqualTo((byte)0x03);
			await Assert.That(chosenSign.Hid).IsEqualTo((byte)0x00);
			await Assert.That(chosenEncrypt.Hid).IsEqualTo((byte)0xFF);
		}
	}

	// Extraction, encryption, encapsulation and verification take H1(ID ‖ hid, N) with the hid of the master key, and the key exchange that of its keys: a master key for which t1 is 0 under one hid has keys under another.
	[Test]
	public async Task IdsWithoutKeysDependOnTheHid()
	{
		byte[] id = "nobody"u8.ToArray();
		const byte hid = 0x05;
		byte[] masterKey = Encode(N - ReferenceHash(0x01, [.. id, hid]));
		using SM9SignatureMasterKey sign = SM9SignatureMasterKey.ImportPrivateKey(masterKey, hid);
		using SM9SignatureMasterKey signDefault = SM9SignatureMasterKey.ImportPrivateKey(masterKey);
		using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.ImportPrivateKey(masterKey, hid);
		using SM9EncryptionMasterKey encryptDefault = SM9EncryptionMasterKey.ImportPrivateKey(masterKey);
		using SM9SignatureKey other = sign.ExtractKey("somebody"u8);
		using SM9SignatureKey key = signDefault.ExtractKey(id);
		using SM9EncryptionKey decryptor = encryptDefault.ExtractKey(id);
		using SM9KeyExchangeKey peer = encrypt.ExtractKeyExchangeKey("somebody"u8, hid);
		byte[] signature = Sign(other, [1]);

		using (Assert.Multiple())
		{
			await Assert.That(() => sign.ExtractKey(id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.ExtractKey(id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encryptDefault.ExtractKeyExchangeKey(id, hid)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.Encrypt([1], new byte[97], id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.Encapsulate(new byte[65], new byte[16], id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => SM9KeyExchange.Create(peer, id, SM9KeyExchangeRole.Initiator)).ThrowsExactly<CryptographicException>();
			await Assert.That(sign.Verify([1], signature, "somebody"u8)).IsTrue();
			await Assert.That(signDefault.Verify([1], Sign(key, [1]), id)).IsTrue();
			await Assert.That(Decrypt(decryptor, Encrypt(encryptDefault, [1], id))).IsEquivalentTo((byte[])[1], CollectionOrdering.Matching);
			await Assert.That(() => encrypt.ExtractKeyExchangeKey(id).Dispose()).ThrowsNothing();
		}
	}

	// GM/T 0044.2 to 0044.4, Sec. 5.3: if t1 = H1(ID ‖ hid, N) + k is 0, the KGC must generate a new master key, so the extraction throws, and the user public key of the ID, [H1(ID ‖ hid, N)]P1 + Ppub-e or [H1(ID ‖ hid, N)]P2 + Ppub-s, is the point at infinity: encryption, encapsulation and the key exchange to it throw, and no signature of it verifies.
	[Test]
	public async Task IdsWithoutKeysAreRejected()
	{
		byte[] id = "nobody"u8.ToArray();
		using SM9SignatureMasterKey sign = SM9SignatureMasterKey.ImportPrivateKey(Encode(N - ReferenceHash(0x01, [.. id, 0x01])));
		using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.ImportPrivateKey(Encode(N - ReferenceHash(0x01, [.. id, 0x03])));
		using SM9EncryptionMasterKey exchange = SM9EncryptionMasterKey.ImportPrivateKey(Encode(N - ReferenceHash(0x01, [.. id, 0x02])));
		using SM9SignatureKey other = sign.ExtractKey("somebody"u8);
		using SM9KeyExchangeKey peer = exchange.ExtractKeyExchangeKey("somebody"u8);
		byte[] signature = Sign(other, [1]);

		using (Assert.Multiple())
		{
			await Assert.That(() => sign.ExtractKey(id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.ExtractKey(id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => exchange.ExtractKeyExchangeKey(id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.Encrypt([1], new byte[97], id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.EncryptDer([1], new byte[200], id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => encrypt.Encapsulate(new byte[65], new byte[16], id)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => SM9KeyExchange.Create(peer, id, SM9KeyExchangeRole.Initiator)).ThrowsExactly<CryptographicException>();
			await Assert.That(sign.Verify([1], signature, id)).IsFalse();
			await Assert.That(sign.Verify([1], signature, "somebody"u8)).IsTrue();
		}
	}

	[Test]
	public async Task PublicKeysCannotExtract()
	{
		using SM9SignatureMasterKey signMaster = SM9SignatureMasterKey.GenerateKey();
		using SM9EncryptionMasterKey encryptMaster = SM9EncryptionMasterKey.GenerateKey();
		using SM9SignatureMasterKey sign = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(signMaster));
		using SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.ImportPublicKey(ExportPublicKey(encryptMaster));

		using (Assert.Multiple())
		{
			await Assert.That(() => sign.ExtractKey("Alice"u8)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => sign.ExportPrivateKey(new byte[32])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => encrypt.ExtractKey("Alice"u8)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => encrypt.ExtractKeyExchangeKey("Alice"u8)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => encrypt.ExportPrivateKey(new byte[32])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => sign.ExportPublicKey(new byte[128])).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => encrypt.ExportPublicKey(new byte[64])).Throws<ArgumentException>().WithParameterName("destination");
		}
	}

	[Test]
	public async Task DisposedKeysThrow()
	{
		SM9SignatureMasterKey sign = SM9SignatureMasterKey.GenerateKey();
		SM9EncryptionMasterKey encrypt = SM9EncryptionMasterKey.GenerateKey();
		_ = Encrypt(encrypt, [1], "Alice"u8.ToArray());
		sign.Dispose();
		sign.Dispose();
		encrypt.Dispose();
		encrypt.Dispose();
		FieldElement<SM9Order> storedSign = (FieldElement<SM9Order>)typeof(SM9SignatureMasterKey).GetField("_privateKey", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(sign)!;
		FieldElement<SM9Order> storedEncrypt = (FieldElement<SM9Order>)typeof(SM9EncryptionMasterKey).GetField("_privateKey", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(encrypt)!;

		using (Assert.Multiple())
		{
			await Assert.That(FieldElement<SM9Order>.GetLimbs(in storedSign).ToArray()).All(static limb => limb is 0);
			await Assert.That(FieldElement<SM9Order>.GetLimbs(in storedEncrypt).ToArray()).All(static limb => limb is 0);
			await Assert.That(() => sign.HasPrivateKey).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sign.Hid).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sign.ExtractKey("Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sign.Verify([], new byte[97], "Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sign.VerifyDer([], new byte[104], "Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sign.ExportPublicKey(new byte[129])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.HasPrivateKey).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.Hid).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.ExtractKey("Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.ExtractKeyExchangeKey("Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.Encrypt([1], new byte[97], "Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.EncryptDer([1], new byte[200], "Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.Encapsulate(new byte[65], new byte[16], "Alice"u8)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => encrypt.ExportPublicKey(new byte[65])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	private static bool Throws(Func<IDisposable> import)
	{
		try
		{
			using IDisposable _ = import();
			return false;
		}
		catch (ArgumentException e) when (e.ParamName is "source")
		{
			return true;
		}
	}
}
