using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;
using CryptoBase.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Vectors;
using static CryptoBase.Tests.SM9.SM9TestUtils;

namespace CryptoBase.Tests.SM9;

// The examples of GM/T 0044.5-2016, the same as those of GB/T 38635.2-2020: Annex A (the signature), B (the key exchange), C (the key encapsulation) and D (encryption), with the master keys and random numbers that they print. The values of the pairings and powers are those of SM9Vectors, which the tests of the mathematics check; the steps here check H1, H2, t1 and t2, the keys, the KDF inputs and outputs and the encodings.
public class SM9AnnexTest
{
	private static readonly byte[] Alice = "Alice"u8.ToArray();

	private static readonly byte[] Bob = "Bob"u8.ToArray();

	// A.2.
	[Test]
	public async Task SignatureOfAnnexA()
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.ImportPrivateKey(Scalar(SignMasterKey));
		using SM9SignatureKey key = master.ExtractKey(Alice);
		byte[] message = "Chinese IBS standard"u8.ToArray();
		SM9Kgc.ExtractScalar(Element(SignMasterKey), Alice, 0x01, out FieldElement<SM9Order> t2);
		SM9Hash.StartH2(message, out SM3KdfState prefix);
		bool signed = key.TrySign(in prefix, Element(SignR), key.GetBase(), out FieldElement<SM9Order> h, out SM9AffinePoint<SM9Fp> s);
		byte[] signature = new byte[SM9SignatureKey.SignatureLength];
		FieldElement<SM9Order>.Export(in h, signature.AsSpan(0, 32));
		SM9G1.Encode(in s, signature.AsSpan(32));
		byte[] expectedSignature = Hex($"{SignH} 04 {SignatureX} {SignatureY}");
		byte[] expectedDer = Hex($"3066 0420 {SignH} 034200 04 {SignatureX} {SignatureY}");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(master)).IsEquivalentTo(Hex($"04 {SignPublicX1} {SignPublicX0} {SignPublicY1} {SignPublicY0}"), CollectionOrdering.Matching);
			await Assert.That(H1Value(Alice, 0x01)).IsEqualTo(Parse(VerifyH1));
			await Assert.That((Parse(VerifyH1) + Parse(SignMasterKey)) % N).IsEqualTo(Parse("2ACD7773 BD808842 F841D35F 87070D79 5F6AF8F3 F08C915E 760A4511 86B3F59F"));
			await Assert.That(Value(in t2)).IsEqualTo(Parse(SignT2));
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(Hex($"04 {SignKeyX} {SignKeyY}"), CollectionOrdering.Matching);
			await Assert.That(signed).IsTrue();
			await Assert.That(Value(in h)).IsEqualTo(Parse(SignH));
			await Assert.That((Parse(SignR) - Parse(SignH) + N) % N).IsEqualTo(Parse(SignL));
			await Assert.That(signature).IsEquivalentTo(expectedSignature, CollectionOrdering.Matching);
			await Assert.That(master.Verify(message, expectedSignature, Alice)).IsTrue();
			await Assert.That(master.VerifyDer(message, expectedDer, Alice)).IsTrue();
		}
	}

	// A.2: H2(M ‖ w, N) for the w of the example, and the verification as a verifier with the master public key alone, twice, so that the second takes the table of g.
	[Test]
	public async Task VerificationOfAnnexA()
	{
		byte[] message = "Chinese IBS standard"u8.ToArray();
		byte[] w = Hex(SignW);
		using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(Hex($"04 {SignPublicX1} {SignPublicX0} {SignPublicY1} {SignPublicY0}"));
		byte[] signature = Hex($"{SignH} 04 {SignatureX} {SignatureY}");

		using (Assert.Multiple())
		{
			await Assert.That(ReferenceHash(0x02, [.. message, .. w])).IsEqualTo(Parse(SignH));
			await Assert.That(H2Value(message, w)).IsEqualTo(Parse(SignH));
			await Assert.That(verifier.Verify(message, signature, Alice)).IsTrue();
			await Assert.That(verifier.Verify(message, signature, Alice)).IsTrue();
			await Assert.That(verifier.Verify(message, signature, Bob)).IsFalse();
			await Assert.That(verifier.Verify("Chinese IBS standarD"u8, signature, Alice)).IsFalse();
		}
	}

	// B.2, for the key exchange keys of hid = 0x03 that the example extracts. Its steps A1 and B1 print ID ‖ hid as 426F6202 and 416C696365 02, but the H1 values they print are those of 03, as are the keys deA and deB of the example and so the RA, RB, g1, g2 and g3 that follow: GM/T 0044.3, Sec. 5.3, has one identifier hid of the encryption private key for the extraction and for QA and QB, and the protocol works only with that. The default hid of the key exchange keys is the 0x02 that steps A1 and B1 print, which gives other values for the same master key and random numbers, so the keys here are extracted and imported with 0x03.
	[Test]
	public async Task KeyExchangeOfAnnexB()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(ExchangeMasterKey));
		using SM9KeyExchangeKey alice = master.ExtractKeyExchangeKey(Alice, 0x03);
		byte[] expectedBob = Hex($"04 {ExchangeKeyBX1} {ExchangeKeyBX0} {ExchangeKeyBY1} {ExchangeKeyBY0}");
		byte[] publicKey = ExportPublicKey(master);
		using SM9KeyExchangeKey bob = SM9KeyExchangeKey.ImportPrivateKey(expectedBob, publicKey, Bob, 0x03);
		using SM9KeyExchangeKey extractedBob = master.ExtractKeyExchangeKey(Bob, 0x03);
		SM9Kgc.ExtractScalar(Element(ExchangeMasterKey), Alice, 0x03, out FieldElement<SM9Order> t2);
		SM9Kgc.ExtractScalar(Element(ExchangeMasterKey), Bob, 0x03, out FieldElement<SM9Order> t4);
		using SM9KeyExchange initiator = SM9KeyExchange.Create(alice, Bob, SM9KeyExchangeRole.Initiator, Fill(Scalar(ExchangeRA)));
		using SM9KeyExchange responder = SM9KeyExchange.Create(bob, Alice, SM9KeyExchangeRole.Responder, Fill(Scalar(ExchangeRB)));
		byte[] ephemeralA = ExportEphemeral(initiator);
		byte[] ephemeralB = ExportEphemeral(responder);
		byte[] keyB = new byte[16];
		byte[] sB = new byte[32];
		byte[] s2 = new byte[32];
		byte[] keyA = new byte[16];
		byte[] sA = new byte[32];
		byte[] s1 = new byte[32];
		bool derivedB = responder.TryDeriveKey(ephemeralA, keyB, sB, s2);
		bool derivedA = initiator.TryDeriveKey(ephemeralB, keyA, sA, s1);
		byte[] expectedKey = Hex("68B20D30 77EA6E2B 82531583 6FDBC633");
		byte[] expectedSB = Hex("E122B3BF A8965562 AA0A4A92 B671A193 352F2832 8A129BFF 45C4DD26 2EBCB9EE");
		byte[] expectedSA = Hex("6CD52312 17E73D80 548A1A65 DED17849 3F4282E6 E471FE3E F62271EA 758470E6");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(master)).IsEquivalentTo(Hex($"04 {ExchangePublicX} {ExchangePublicY}"), CollectionOrdering.Matching);
			await Assert.That(H1Value(Alice, 0x03)).IsEqualTo(Parse("32DEE8AA D2DF2DB7 2C087F89 AA5FDA45 1B94D31A BD03F8E3 6A057FE2 CD160014"));
			await Assert.That(H1Value(Bob, 0x03)).IsEqualTo(Parse("9CB1F628 8CE0E510 43CE7234 4582FFC3 01E0A812 A7F5F200 4B85547A 24B82716"));
			await Assert.That(H1Value(Bob, 0x02)).IsNotEqualTo(Parse("9CB1F628 8CE0E510 43CE7234 4582FFC3 01E0A812 A7F5F200 4B85547A 24B82716"));
			await Assert.That(Value(in t2)).IsEqualTo(Parse(ExchangeT2));
			await Assert.That(Value(in t4)).IsEqualTo(Parse(ExchangeT4));
			await Assert.That(ExportPrivateKey(alice)).IsEquivalentTo(Hex($"04 {ExchangeKeyAX1} {ExchangeKeyAX0} {ExchangeKeyAY1} {ExchangeKeyAY0}"), CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(extractedBob)).IsEquivalentTo(expectedBob, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(bob)).IsEquivalentTo(expectedBob, CollectionOrdering.Matching);
			await Assert.That(() => SM9KeyExchangeKey.ImportPrivateKey(expectedBob, publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
			await Assert.That(UserPublicKey(master, Bob, 0x03)).IsEquivalentTo(Hex($"04 {ExchangeQBX} {ExchangeQBY}"), CollectionOrdering.Matching);
			await Assert.That(UserPublicKey(master, Alice, 0x03)).IsEquivalentTo(Hex($"04 {ExchangeQAX} {ExchangeQAY}"), CollectionOrdering.Matching);
			await Assert.That(ephemeralA).IsEquivalentTo(Hex($"04 {ExchangePointAX} {ExchangePointAY}"), CollectionOrdering.Matching);
			await Assert.That(ephemeralB).IsEquivalentTo(Hex($"04 {ExchangePointBX} {ExchangePointBY}"), CollectionOrdering.Matching);
			await Assert.That(derivedB).IsTrue();
			await Assert.That(derivedA).IsTrue();
			await Assert.That(keyB).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(keyA).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(sB).IsEquivalentTo(expectedSB, CollectionOrdering.Matching);
			await Assert.That(s1).IsEquivalentTo(expectedSB, CollectionOrdering.Matching);
			await Assert.That(sA).IsEquivalentTo(expectedSA, CollectionOrdering.Matching);
			await Assert.That(s2).IsEquivalentTo(expectedSA, CollectionOrdering.Matching);
		}
	}

	// B.2 from the printed values alone: the inputs of the KDF and of the confirmations, as the example writes them out, with RA and RB as x ‖ y and g1, g2 and g3 in the order of the encoding.
	[Test]
	public async Task AnnexBValuesFollowFromTheHashes()
	{
		byte[] ephemeralA = Hex($"{ExchangePointAX} {ExchangePointAY}");
		byte[] ephemeralB = Hex($"{ExchangePointBX} {ExchangePointBY}");
		byte[] g1 = Hex(ExchangeG1);
		byte[] g2 = Hex(ExchangeG2);
		byte[] g3 = Hex(ExchangeG3);
		byte[] inner = Sm3(g2, g3, Alice, Bob, ephemeralA, ephemeralB);

		using (Assert.Multiple())
		{
			await Assert.That(ReferenceKdf([.. Alice, .. Bob, .. ephemeralA, .. ephemeralB, .. g1, .. g2, .. g3], 16)).IsEquivalentTo(Hex("68B20D30 77EA6E2B 82531583 6FDBC633"), CollectionOrdering.Matching);
			await Assert.That(inner).IsEquivalentTo(Hex("B6F6F71E FCEA0E02 DF198422 28AD50A9 EFD7A4B2 F12DAFE2 BE354AD0 107547F1"), CollectionOrdering.Matching);
			await Assert.That(Sm3([0x82], g1, inner)).IsEquivalentTo(Hex("E122B3BF A8965562 AA0A4A92 B671A193 352F2832 8A129BFF 45C4DD26 2EBCB9EE"), CollectionOrdering.Matching);
			await Assert.That(Sm3([0x83], g1, inner)).IsEquivalentTo(Hex("6CD52312 17E73D80 548A1A65 DED17849 3F4282E6 E471FE3E F62271EA 758470E6"), CollectionOrdering.Matching);
		}
	}

	// C.2: a key of 256 bits.
	[Test]
	public async Task KeyEncapsulationOfAnnexC()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey));
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		SM9Kgc.ExtractScalar(Element(EncryptMasterKey), Bob, 0x03, out FieldElement<SM9Order> t2);
		byte[] encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
		byte[] sharedKey = new byte[32];
		master.Encapsulate(encapsulation, sharedKey, Bob, Fill(Scalar(EncapsulateR)));
		byte[] expectedEncapsulation = Hex($"04 {EncapsulateCX} {EncapsulateCY}");
		byte[] expectedKey = Hex("4FF5CF86 D2AD40C8 F4BAC98D 76ABDBDE 0C0E2F0A 829D3F91 1EF5B2BC E0695480");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(master)).IsEquivalentTo(Hex($"04 {EncryptPublicX} {EncryptPublicY}"), CollectionOrdering.Matching);
			await Assert.That((H1Value(Bob, 0x03) + Parse(EncryptMasterKey)) % N).IsEqualTo(Parse("9CB3E416 C459D952 3CAD160E 3F8DCC11 09CEDEDB E78FFA61 D67A01FF F3964338"));
			await Assert.That(Value(in t2)).IsEqualTo(Parse(EncryptT2));
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(Hex($"04 {EncryptKeyX1} {EncryptKeyX0} {EncryptKeyY1} {EncryptKeyY0}"), CollectionOrdering.Matching);
			await Assert.That(UserPublicKey(master, Bob, 0x03)).IsEquivalentTo(Hex($"04 {EncapsulateQBX} {EncapsulateQBY}"), CollectionOrdering.Matching);
			await Assert.That(encapsulation).IsEquivalentTo(expectedEncapsulation, CollectionOrdering.Matching);
			await Assert.That(sharedKey).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(ReferenceKdf([.. Hex($"{EncapsulateCX} {EncapsulateCY}"), .. Hex(EncapsulateW), .. Bob], 32)).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(key, expectedEncapsulation, 32)).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
		}
	}

	// D.2, the stream cipher of the KDF: C = C1 ‖ C3 ‖ C2 with C1 as x ‖ y, and K = K1 ‖ K2 of 416 bits, which the encapsulation of C1 gives too.
	[Test]
	public async Task EncryptionOfAnnexD()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey));
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] message = "Chinese IBE standard"u8.ToArray();
		byte[] ciphertext = new byte[SM9EncryptionMasterKey.GetCiphertextLength(message.Length)];
		int written = master.Encrypt(message, ciphertext, Bob, Fill(Scalar(EncryptR)));
		byte[] der = new byte[SM9EncryptionMasterKey.GetDerCiphertextLength(message.Length)];
		int derWritten = master.EncryptDer(message, der, Bob, Fill(Scalar(EncryptR)));
		byte[] c1 = Hex($"{EncryptC1X} {EncryptC1Y}");
		byte[] c3 = Hex("BA672387 BCD6DE50 16A158A5 2BB2E7FC 429197BC AB70B25A FEE37A2B 9DB9F367");
		byte[] c2 = Hex("1B5F5B0E 95148968 2F3E64E1 378CDD5D A9513B1C");
		byte[] expectedKey = Hex("58373260 F067EC48 667C21C1 44F8BC33 CD304978 8651FFD5 F738003E 51DF3117 4D0E4E40 2FD87F45 81B612F7 4259DB57 4F67ECE6");
		byte[] expectedDer = Hex($"30 7F 020100 034200 04 {EncryptC1X} {EncryptC1Y} 0420 BA672387 BCD6DE50 16A158A5 2BB2E7FC 429197BC AB70B25A FEE37A2B 9DB9F367 0414 1B5F5B0E 95148968 2F3E64E1 378CDD5D A9513B1C");

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(116);
			await Assert.That(ciphertext).IsEquivalentTo([.. c1, .. c3, .. c2], CollectionOrdering.Matching);
			await Assert.That(ReferenceKdf([.. c1, .. Hex(EncryptW), .. Bob], 52)).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(key, [0x04, .. c1], 52)).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(Sm3(c2, expectedKey.AsSpan(20).ToArray())).IsEquivalentTo(c3, CollectionOrdering.Matching);
			await Assert.That(Decrypt(key, ciphertext)).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(der.AsSpan(0, derWritten).ToArray()).IsEquivalentTo(expectedDer, CollectionOrdering.Matching);
			await Assert.That(DecryptDer(key, expectedDer)).IsEquivalentTo(message, CollectionOrdering.Matching);
		}
	}

	// The master keys, r and ID of C.2 and D.2 with keys and plaintexts of many KDF blocks, around the groups of vector lanes and the chunks that take the key stream: w does not depend on the message, so K comes from the reference KDF, and C2 = M ⊕ K1 and C3 = SM3(C2 ‖ K2). The private key recovers K, as an encapsulation of C1 or of C, and the plaintext.
	[Test]
	public async Task LongKeysAndPlaintextsWithTheValuesOfAnnexesCAndD()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey));
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] c1 = Hex($"{EncryptC1X} {EncryptC1Y}");
		byte[] c = Hex($"{EncapsulateCX} {EncapsulateCY}");
		List<string> failures = [];

		foreach (int length in (int[])[33, 96, 97, 129, 288, 545, 1056, 4095, 4096, 4097, 4127, 4128, 4129, 8225])
		{
			byte[] message = [.. Enumerable.Range(0, length).Select(static i => (byte)(i * 167 + 11))];
			byte[] keyStream = ReferenceKdf([.. c1, .. Hex(EncryptW), .. Bob], length + 32);
			byte[] c2 = [.. message.Zip(keyStream, static (m, k) => (byte)(m ^ k))];
			byte[] expected = [.. c1, .. Sm3(c2, keyStream.AsSpan(length).ToArray()), .. c2];
			byte[] ciphertext = new byte[SM9EncryptionMasterKey.GetCiphertextLength(length)];
			_ = master.Encrypt(message, ciphertext, Bob, Fill(Scalar(EncryptR)));

			if (!ciphertext.AsSpan().SequenceEqual(expected) || Decrypt(key, expected) is not { } decrypted || !decrypted.AsSpan().SequenceEqual(message) || Decapsulate(key, [0x04, .. c1], length + 32) is not { } recovered || !recovered.AsSpan().SequenceEqual(keyStream))
			{
				failures.Add($"a plaintext of {length} bytes");
			}

			byte[] encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
			byte[] sharedKey = new byte[length];
			master.Encapsulate(encapsulation, sharedKey, Bob, Fill(Scalar(EncapsulateR)));
			byte[] expectedKey = ReferenceKdf([.. c, .. Hex(EncapsulateW), .. Bob], length);

			if (!sharedKey.AsSpan().SequenceEqual(expectedKey) || Decapsulate(key, encapsulation, length) is not { } decapsulated || !decapsulated.AsSpan().SequenceEqual(expectedKey))
			{
				failures.Add($"a key of {length} bytes");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// D.2 b), the variant with a block cipher, which this library leaves out as GM/T 0044.4, Sec. 7.1, fixes neither the mode nor the padding: the example takes SM4 in CBC with a zero IV and the padding of PKCS #7, K1 of 128 bits and K2 of 256, and its values follow from the same key stream.
	[Test]
	public async Task BlockCipherExampleOfAnnexDFollowsFromTheKeyStream()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey));
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] k = Decapsulate(key, Hex($"04 {EncryptC1X} {EncryptC1Y}"), 48)!;
		byte[] padded = [.. "Chinese IBE standard"u8, .. Enumerable.Repeat((byte)12, 12)];
		byte[] c2 = new byte[padded.Length];
		byte[] chain = new byte[16];

		using (SM4Cipher cipher = SM4Cipher.Create(k.AsSpan(0, 16)))
		{
			for (int offset = 0; offset < padded.Length; offset += 16)
			{
				byte[] block = [.. padded.AsSpan(offset, 16).ToArray().Zip(chain, static (a, b) => (byte)(a ^ b))];
				cipher.EncryptBlock(block, chain);
				chain.CopyTo(c2, offset);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(k).IsEquivalentTo(Hex("58373260 F067EC48 667C21C1 44F8BC33 CD304978 8651FFD5 F738003E 51DF3117 4D0E4E40 2FD87F45 81B612F7 4259DB57"), CollectionOrdering.Matching);
			await Assert.That(c2).IsEquivalentTo(Hex("E05B6FAC 6F11B965 268C994F 00DBA7A8 132C9574 5B2CACB3 82FBFD90 6D9BA86A"), CollectionOrdering.Matching);
			await Assert.That(Sm3(c2, k.AsSpan(16).ToArray())).IsEquivalentTo(Hex("12AF121D E3795AA5 14D0C6E7 949CE479 807E8B03 140DCA09 D18DD075 E47EB03C"), CollectionOrdering.Matching);
		}
	}

	private static FieldElement<SM9Order> Element(string hex)
	{
		FieldElement<SM9Order>.ImportReduced(Scalar(hex), out FieldElement<SM9Order> scalar);
		return scalar;
	}

	private static BigInteger Value(in FieldElement<SM9Order> scalar)
	{
		byte[] bytes = new byte[32];
		FieldElement<SM9Order>.Export(in scalar, bytes);
		return new BigInteger(bytes, true, true);
	}

	private static BigInteger H1Value(byte[] id, byte hid)
	{
		SM9Hash.H1(id, hid, out FieldElement<SM9Order> h1);
		return Value(in h1);
	}

	private static BigInteger H2Value(byte[] message, byte[] w)
	{
		SM9Hash.StartH2(message, out SM3KdfState state);
		state.Append(w);
		SM9Hash.Finish(in state, out FieldElement<SM9Order> h2);
		return Value(in h2);
	}

	private static byte[] UserPublicKey(SM9EncryptionMasterKey master, byte[] id, byte hid)
	{
		SM9G1.TryDecode(ExportPublicKey(master), out SM9AffinePoint<SM9Fp> publicKey);
		bool finite = SM9Kgc.TryGetUserPublicKey(id, hid, in publicKey, out SM9AffinePoint<SM9Fp> q);
		byte[] encoded = new byte[SM9G1.EncodedLength];
		SM9G1.Encode(in q, encoded);
		return finite ? encoded : [];
	}
}
