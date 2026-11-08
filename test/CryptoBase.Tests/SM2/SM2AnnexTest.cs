using CryptoBase.Abstractions.Signatures;
using CryptoBase.EllipticCurves;
using CryptoBase.SM2;
using CryptoBase.Tests.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.SM2.SM2TestUtils;

namespace CryptoBase.Tests.SM2;

// The examples of GB/T 32918.5-2017 on the recommended curve, Annex A (the signature), Annex B (the key exchange) and Annex C (encryption), which are those of GM/T 0003.5-2012; both IDs are "1234567812345678". Each published value is also recomputed with the BigInteger reference, so that a mistyped constant cannot pass.
public class SM2AnnexTest
{
	private static readonly byte[] SignerPrivateKey = Hex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8");

	private static readonly CurvePoint SignerPublicKey = new(Integer("09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"), Integer("CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"));

	private static readonly byte[] Nonce = Hex("59276E27 D506861A 16680F3A D9C02DCC EF3CC1FA 3CDBE4CE 6D54B80D EAC1BC21");

	[Test]
	public async Task AnnexAValuesFollowFromTheReference()
	{
		BigInteger d = ModulusCase.Decode(SignerPrivateKey);
		BigInteger k = ModulusCase.Decode(Nonce);
		byte[] z = ReferenceZ(SM2Key.DefaultId, SignerPublicKey);
		BigInteger e = ModulusCase.Decode(Sm3(z, "message digest"u8.ToArray()));
		CurvePoint? kG = Reference.Multiply(Reference.Generator, k);
		BigInteger r = (e + kG!.X) % N;
		BigInteger s = ECReference.Inverse((1 + d) % N, N) * ((k - r * d) % N + N) % N;

		using (Assert.Multiple())
		{
			await Assert.That(Reference.PublicKey(d)).IsEqualTo(SignerPublicKey);
			await Assert.That(z).IsEquivalentTo(Hex("B2E14C5C 79C6DF5B 85F4FE7E D8DB7A26 2B9DA7E0 7CCB0EA9 F4747B8C CDA8A4F3"), CollectionOrdering.Matching);
			await Assert.That(e).IsEqualTo(Integer("F0B43E94 BA45ACCA ACE692ED 534382EB 17E6AB5A 19CE7B31 F4486FDF C0D28640"));
			await Assert.That(kG).IsEqualTo(new CurvePoint(Integer("04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73"), Integer("E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0")));
			await Assert.That(ECReference.Inverse(1 + d, N)).IsEqualTo(Integer("4DFE9D9C 1F5901D4 E6F58E4E C3D04567 822D2550 F9B88E82 6D1B5B3A B9CD0FE0"));
			await Assert.That(r).IsEqualTo(Integer("F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3"));
			await Assert.That(s).IsEqualTo(Integer("B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA"));
			await Assert.That((r + s) % N).IsEqualTo(Integer("A756E531 27F3F43B 851C47CF EEFD9E43 A2D133CA 258EF4EA 73FBF468 3ACDA13A"));
		}
	}

	// A.2: the public key, Z, and r and s from the nonce of the example.
	[Test]
	public async Task SignatureOfAnnexA()
	{
		using SM2Key key = SM2Key.ImportPrivateKey(SignerPrivateKey);
		byte[] message = "message digest"u8.ToArray();
		byte[] z = new byte[32];
		key.GetState().ComputeZ(SM2Key.DefaultId, z);
		FieldElement<SM2Order>.ImportReduced(Sm3(z, message), out FieldElement<SM2Order> e);
		bool signed = key.GetState().TrySign(in e, Scalar(ModulusCase.Decode(Nonce)), out FieldElement<SM2Order> r, out FieldElement<SM2Order> s);
		byte[] signature = DerSignature(Value(in r), Value(in s));
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		key.ExportPublicKey(publicKey);

		using (Assert.Multiple())
		{
			await Assert.That(publicKey).IsEquivalentTo(EncodePoint(SignerPublicKey), CollectionOrdering.Matching);
			await Assert.That(z).IsEquivalentTo(Hex("B2E14C5C 79C6DF5B 85F4FE7E D8DB7A26 2B9DA7E0 7CCB0EA9 F4747B8C CDA8A4F3"), CollectionOrdering.Matching);
			await Assert.That(signed).IsTrue();
			await Assert.That(Value(in r)).IsEqualTo(Integer("F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3"));
			await Assert.That(Value(in s)).IsEqualTo(Integer("B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA"));
			await Assert.That(key.Verify(message, signature)).IsTrue();
			await Assert.That(key.Verify(message, signature, "1234567812345678"u8)).IsTrue();
		}
	}

	// A.2, as a verifier with the public key alone, twice, so that the second verification takes the table of the key.
	[Test]
	public async Task VerificationOfAnnexA()
	{
		using SM2Key key = SM2Key.ImportPublicKey(EncodePoint(SignerPublicKey));
		byte[] message = "message digest"u8.ToArray();
		byte[] signature = DerSignature(Integer("F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3"), Integer("B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA"));

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(message, signature)).IsTrue();
			await Assert.That(key.Verify(message, signature)).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.SM2SM3, message, signature)).IsTrue();
			await Assert.That(key.Verify(message, signature, "1234567812345679"u8)).IsFalse();
			await Assert.That(key.Verify("message digesT"u8, signature)).IsFalse();
		}
	}

	[Test]
	public async Task AnnexCValuesFollowFromTheReference()
	{
		BigInteger k = ModulusCase.Decode(Nonce);
		CurvePoint? kP = Reference.Multiply(SignerPublicKey, k);
		byte[] message = "encryption standard"u8.ToArray();
		byte[] t = ReferenceKdf([.. Encode(kP!.X), .. Encode(kP.Y)], message.Length);

		using (Assert.Multiple())
		{
			await Assert.That(kP).IsEqualTo(new CurvePoint(Integer("335E18D7 51E51F04 0E27D468 138B7AB1 DC86AD7F 981D7D41 6222FD6A B3ED230D"), Integer("AB743EBC FB22D64F 7B6AB791 F70658F2 5B48FA93 E54064FD BFBED3F0 BD847AC9")));
			await Assert.That(t).IsEquivalentTo(Hex("44E60FDB F0BAE814 37665374 BEF26749 046C9E"), CollectionOrdering.Matching);
			await Assert.That(message.Zip(t, static (m, key) => (byte)(m ^ key)).ToArray()).IsEquivalentTo(Hex("21886CA9 89CA9C7D 58087307 CA93092D 651EFA"), CollectionOrdering.Matching);
			await Assert.That(Sm3(Encode(kP.X), message, Encode(kP.Y))).IsEquivalentTo(Hex("59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766"), CollectionOrdering.Matching);
		}
	}

	// C.2: the ciphertext C1 ‖ C3 ‖ C2 from the k of the example, and its SM2Cipher of GB/T 35276-2017.
	[Test]
	public async Task EncryptionOfAnnexC()
	{
		using SM2Key decryptor = SM2Key.ImportPrivateKey(SignerPrivateKey);
		using SM2Key encryptor = SM2Key.ImportPublicKey(EncodePoint(SignerPublicKey));
		byte[] message = "encryption standard"u8.ToArray();
		byte[] expected = AnnexCCiphertext();
		byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(message.Length)];
		int written = encryptor.Encrypt(message, ciphertext, Fill(Nonce));
		byte[] der = new byte[SM2Key.GetMaxDerCiphertextLength(message.Length)];
		int derWritten = encryptor.EncryptDer(message, der, Fill(Nonce));
		byte[] expectedDer = Hex("307C0220 04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73 022100E8 58F9D81E 5430A57B 36DAAB8F 950A3C64 E6EE6A63 094D9928 3AFF767E 124DF004 2059983C 18F809E2 62923C53 AEC295D3 0383B54E 39D609D1 60AFCB19 08D0BD87 66041321 886CA989 CA9C7D58 087307CA 93092D65 1EFA");

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(expected.Length);
			await Assert.That(ciphertext).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(der.AsSpan(0, derWritten).ToArray()).IsEquivalentTo(expectedDer, CollectionOrdering.Matching);
			await Assert.That(expectedDer).IsEquivalentTo(DerCiphertext(Integer("04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73"), Integer("E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0"), Hex("59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766"), Hex("21886CA9 89CA9C7D 58087307 CA93092D 651EFA")), CollectionOrdering.Matching);
			await Assert.That(Decrypt(decryptor, expected)).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(DecryptDer(decryptor, expectedDer)).IsEquivalentTo(message, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task AnnexBValuesFollowFromTheReference()
	{
		BigInteger dA = Integer("81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029");
		BigInteger dB = Integer("78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5");
		BigInteger rA = Integer("D4DE1547 4DB74D06 491C440D 305E0124 00990F3E 390C7E87 153C12DB 2EA60BB3");
		BigInteger rB = Integer("7E071248 14B30948 9125EAED 10111316 4EBF0F34 58C5BD88 335C1F9D 596243D6");
		CurvePoint pA = Reference.PublicKey(dA);
		CurvePoint pB = Reference.PublicKey(dB);
		CurvePoint ephemeralA = Reference.PublicKey(rA);
		CurvePoint ephemeralB = Reference.PublicKey(rB);
		BigInteger xA = (BigInteger.One << 127) + (ephemeralA.X & (BigInteger.One << 127) - 1);
		BigInteger xB = (BigInteger.One << 127) + (ephemeralB.X & (BigInteger.One << 127) - 1);
		BigInteger tA = (dA + xA * rA) % N;
		BigInteger tB = (dB + xB * rB) % N;
		CurvePoint? u = Reference.Multiply(Reference.Add(pB, Reference.Multiply(ephemeralB, xB)), tA);
		CurvePoint? v = Reference.Multiply(Reference.Add(pA, Reference.Multiply(ephemeralA, xA)), tB);
		byte[] zA = ReferenceZ(SM2Key.DefaultId, pA);
		byte[] zB = ReferenceZ(SM2Key.DefaultId, pB);
		byte[] inner = Sm3(Encode(u!.X), zA, zB, Encode(ephemeralA.X), Encode(ephemeralA.Y), Encode(ephemeralB.X), Encode(ephemeralB.Y));

		using (Assert.Multiple())
		{
			await Assert.That(EncodePoint(pA)).IsEquivalentTo(Hex("04 160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232 4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F"), CollectionOrdering.Matching);
			await Assert.That(EncodePoint(pB)).IsEquivalentTo(Hex("04 6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D"), CollectionOrdering.Matching);
			await Assert.That(zA).IsEquivalentTo(Hex("3B85A571 79E11E7E 513AA622 991F2CA7 4D1807A0 BD4D4B38 F90987A1 7AC245B1"), CollectionOrdering.Matching);
			await Assert.That(zB).IsEquivalentTo(Hex("79C988D6 3229D97E F19FE02C A1056E01 E6A7411E D24694AA 8F834F4A 4AB022F7"), CollectionOrdering.Matching);
			await Assert.That(xB).IsEqualTo(Integer("FDC2802C DB14CCCC DB0A9047 1F9BD707"));
			await Assert.That(xA).IsEqualTo(Integer("CF608A5D B8FE5CE0 7F150269 40BAE40E"));
			await Assert.That(tB).IsEqualTo(Integer("D0429637 F5A6D5D1 E6C54523 5169DF85 23116306 0A654ECB A0F657FD 629E8DD9"));
			await Assert.That(tA).IsEqualTo(Integer("3D68C0C0 6DC40F17 B9DDFE00 93D3C0E4 969ED112 4A187FA8 AD02F81E 3C11CCE6"));
			await Assert.That(u).IsEqualTo(v);
			await Assert.That(u).IsEqualTo(new CurvePoint(Integer("C558B44B EE5301D9 F52B44D9 39BB5958 4D75B903 4DD6A9FC 82687210 9A65739F"), Integer("3252B35B 191D8AE0 1CD122C0 25204334 C5EACF68 A0CB4854 C6A7D367 ECAD4DE7")));
			await Assert.That(ReferenceKdf([.. Encode(u.X), .. Encode(u.Y), .. zA, .. zB], 16)).IsEquivalentTo(Hex("6C893473 54DE2484 C60B4AB1 FDE4C6E5"), CollectionOrdering.Matching);
			await Assert.That(inner).IsEquivalentTo(Hex("90E2A628 E4F57ABD 78339EA3 3F967D11 A154117B EA442F7B 627D4F4D D047B7F6"), CollectionOrdering.Matching);
			await Assert.That(Sm3([0x02], Encode(u.Y), inner)).IsEquivalentTo(Hex("D3A0FE15 DEE185CE AE907A6B 595CC32A 266ED7B3 367E9983 A896DC32 FA20F8EB"), CollectionOrdering.Matching);
			await Assert.That(Sm3([0x03], Encode(u.Y), inner)).IsEquivalentTo(Hex("18C7894B 3816DF16 CF07B05C 5EC0BEF5 D655D58F 779CC1B4 00A4F388 4644DB88"), CollectionOrdering.Matching);
		}
	}

	// B.2: both parties, with the ephemeral keys of the example and a key of 128 bits. The responder's confirmation is S_B, which the initiator expects as S_1, and the initiator's is S_A, which the responder expects as S_2.
	[Test]
	public async Task KeyExchangeOfAnnexB()
	{
		using SM2Key a = SM2Key.ImportPrivateKey(Hex("81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029"));
		using SM2Key b = SM2Key.ImportPrivateKey(Hex("78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5"));
		using SM2Key publicA = SM2Key.ImportPublicKey(Hex("04 160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232 4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F"));
		using SM2Key publicB = SM2Key.ImportPublicKey(Hex("04 6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D"));
		using SM2KeyExchange initiator = SM2KeyExchange.Create(a, SM2Key.DefaultId, SM2KeyExchangeRole.Initiator, Fill(Hex("D4DE1547 4DB74D06 491C440D 305E0124 00990F3E 390C7E87 153C12DB 2EA60BB3")));
		using SM2KeyExchange responder = SM2KeyExchange.Create(b, SM2Key.DefaultId, SM2KeyExchangeRole.Responder, Fill(Hex("7E071248 14B30948 9125EAED 10111316 4EBF0F34 58C5BD88 335C1F9D 596243D6")));
		byte[] ephemeralA = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
		byte[] ephemeralB = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
		initiator.ExportEphemeralPublicKey(ephemeralA);
		responder.ExportEphemeralPublicKey(ephemeralB);
		byte[] keyB = new byte[16];
		byte[] sB = new byte[32];
		byte[] s2 = new byte[32];
		byte[] keyA = new byte[16];
		byte[] sA = new byte[32];
		byte[] s1 = new byte[32];
		bool derivedB = responder.TryDeriveKey(publicA, SM2Key.DefaultId, ephemeralA, keyB, sB, s2);
		bool derivedA = initiator.TryDeriveKey(publicB, SM2Key.DefaultId, ephemeralB, keyA, sA, s1);
		byte[] expectedSB = Hex("D3A0FE15 DEE185CE AE907A6B 595CC32A 266ED7B3 367E9983 A896DC32 FA20F8EB");
		byte[] expectedSA = Hex("18C7894B 3816DF16 CF07B05C 5EC0BEF5 D655D58F 779CC1B4 00A4F388 4644DB88");

		using (Assert.Multiple())
		{
			await Assert.That(ephemeralA).IsEquivalentTo(Hex("04 64CED1BD BC99D590 049B434D 0FD73428 CF608A5D B8FE5CE0 7F150269 40BAE40E 376629C7 AB21E7DB 26092249 9DDB118F 07CE8EAA E3E7720A FEF6A5CC 062070C0"), CollectionOrdering.Matching);
			await Assert.That(ephemeralB).IsEquivalentTo(Hex("04 ACC27688 A6F7B706 098BC91F F3AD1BFF 7DC2802C DB14CCCC DB0A9047 1F9BD707 2FEDAC04 94B2FFC4 D6853876 C79B8F30 1C6573AD 0AA50F39 FC87181E 1A1B46FE"), CollectionOrdering.Matching);
			await Assert.That(derivedB).IsTrue();
			await Assert.That(derivedA).IsTrue();
			await Assert.That(keyB).IsEquivalentTo(Hex("6C893473 54DE2484 C60B4AB1 FDE4C6E5"), CollectionOrdering.Matching);
			await Assert.That(keyA).IsEquivalentTo(keyB, CollectionOrdering.Matching);
			await Assert.That(sB).IsEquivalentTo(expectedSB, CollectionOrdering.Matching);
			await Assert.That(s1).IsEquivalentTo(expectedSB, CollectionOrdering.Matching);
			await Assert.That(sA).IsEquivalentTo(expectedSA, CollectionOrdering.Matching);
			await Assert.That(s2).IsEquivalentTo(expectedSA, CollectionOrdering.Matching);
		}
	}

	private static byte[] AnnexCCiphertext()
	{
		return Hex("04 04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73 E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0 59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766 21886CA9 89CA9C7D 58087307 CA93092D 651EFA");
	}
}
