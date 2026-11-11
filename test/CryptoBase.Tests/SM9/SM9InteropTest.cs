using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using CryptoBase.SM9;
using System.Formats.Asn1;
using System.Text;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Vectors;
using static CryptoBase.Tests.SM9.SM9TestUtils;

namespace CryptoBase.Tests.SM9;

// Known-answer vectors for the master keys of GM/T 0044.5: signatures and encapsulations whose random numbers are unknown, so checked as a verifier and a decryptor sees them; an SM9Cipher whose C3 takes another MAC; a key exchange with hid = 0x02; and the keys, signatures, ciphertexts, encapsulations and a key exchange of hid = 0x05.
public class SM9InteropTest
{
	private const byte OtherHid = 0x05;

	private static readonly byte[] Alice = "Alice"u8.ToArray();

	private static readonly byte[] Bob = "Bob"u8.ToArray();

	public static IEnumerable<Func<string>> OtherHidSignatures()
	{
		yield return () => "306604206CB5D460E345831645237C3E2A020A4C4A96869B96765C29FF16C88A50AC3BAC034200049115747B942E374AEC808BB1E011A471E0CCBF4894120A8EA230C120024201E483F20D941EF28D75C09D4098A3A88FC64011073F544035B14DACEE1CAF22DA39";
		yield return () => "306604208E439DCFBC99D5570AFB5BCB1571FD771469D3A8D4A6336E821D9F17329063F20342000447DF1649FE61FF826B850F3C4EABBFF4D4810540D3DE45F0BF08B7D719F2720E348292BB9A08820D972D4754D93119AF7451390FEE95B5AA01816ABCBA193F35";
	}

	// The signature master key of GM/T 0044.5, A.2, with hid = 0x05: the signing key of Alice, and DER signatures of the message of the example, whose random numbers are unknown, which verify with that hid alone, as do their h ‖ S.
	[Test]
	[MethodDataSource(nameof(OtherHidSignatures))]
	public async Task SignaturesOfAnotherHidVerify(string signature)
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.ImportPrivateKey(Scalar(SignMasterKey), OtherHid);
		using SM9SignatureKey key = master.ExtractKey(Alice);
		byte[] publicKey = ExportPublicKey(master);
		using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(publicKey, OtherHid);
		using SM9SignatureMasterKey defaultVerifier = SM9SignatureMasterKey.ImportPublicKey(publicKey);
		byte[] privateKey = Hex("049A30C128DAE7ED48FB805D7A105612130C5E8B47FB64FE0B139DC47102D9680F5D92FB96DA1B81A6A3857796DF745D51C376C3BC51271AA0003EB999B5C836BF");
		byte[] message = "Chinese IBS standard"u8.ToArray();
		byte[] der = Hex(signature);
		byte[] raw = [.. der.AsSpan(4, 32), .. der.AsSpan(39)];
		using SM9SignatureKey imported = SM9SignatureKey.ImportPrivateKey(privateKey, publicKey, Alice, OtherHid);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(publicKey).IsEquivalentTo(Hex($"04 {SignPublicX1} {SignPublicX0} {SignPublicY1} {SignPublicY0}"), CollectionOrdering.Matching);
			await Assert.That(verifier.VerifyDer(message, der, Alice)).IsTrue();
			await Assert.That(verifier.Verify(message, raw, Alice)).IsTrue();
			await Assert.That(master.VerifyDer(message, der, Alice)).IsTrue();
			await Assert.That(defaultVerifier.VerifyDer(message, der, Alice)).IsFalse();
			await Assert.That(defaultVerifier.Verify(message, raw, Alice)).IsFalse();
			await Assert.That(() => SM9SignatureKey.ImportPrivateKey(privateKey, publicKey, Alice)).Throws<ArgumentException>().WithParameterName("privateKey");
		}
	}

	// The encryption master key of GM/T 0044.5, C.2 and D.2, with hid = 0x05 and the random numbers of D.2 and C.2: the private key of Bob, the ciphertext as C1 ‖ C3 ‖ C2 and in DER, and an encapsulation of 32 bytes; and an encapsulation whose random number is unknown.
	[Test]
	public async Task EncryptionOfAnotherHidMatchesTheVectors()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey), OtherHid);
		using SM9EncryptionKey key = master.ExtractKey(Bob);
		byte[] privateKey = Hex("0489CF5C8A2249D4C34AF1EC4790D118E2306FFF1559235E37F1A56755224D987E459D664E7C6AD258612D37AF2117A075D7183A17D6412DBF5A5E14306CD6707057887656A84FDB0B7D33C9ADC6C8EE05D48CCACA68BEFCD8576E173C1D07F41FB296BCB3BC99DF63FE274E36B414A2E63CB1EF948AE7C9C9D55BDB7405267DAF");
		byte[] publicKey = ExportPublicKey(master);
		using SM9EncryptionKey imported = SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey, Bob, OtherHid);
		byte[] message = "Chinese IBE standard"u8.ToArray();
		byte[] ciphertext = new byte[SM9EncryptionMasterKey.GetCiphertextLength(message.Length)];
		_ = master.Encrypt(message, ciphertext, Bob, Fill(Scalar(EncryptR)));
		byte[] der = new byte[SM9EncryptionMasterKey.GetDerCiphertextLength(message.Length)];
		int derWritten = master.EncryptDer(message, der, Bob, Fill(Scalar(EncryptR)));
		byte[] encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
		byte[] sharedKey = new byte[32];
		master.Encapsulate(encapsulation, sharedKey, Bob, Fill(Scalar(EncapsulateR)));
		byte[] expectedCiphertext = Hex("3EFF427A46DC228BEEC637AB15E742C1F0DDD682209679CEB38F034EFE7533E12A296103A5AD2AEA979022670953BAAD43C243A2106E8A2E5626BC7897BFEBB99A7B1886B25C08767C326DCB17578E034D3762F96E6A3F4249DCDFEE8BE4C1452A6A9050530AFF0F4836F8D1CDD57C20D689633C");
		byte[] expectedDer = Hex("307F020100034200043EFF427A46DC228BEEC637AB15E742C1F0DDD682209679CEB38F034EFE7533E12A296103A5AD2AEA979022670953BAAD43C243A2106E8A2E5626BC7897BFEBB904209A7B1886B25C08767C326DCB17578E034D3762F96E6A3F4249DCDFEE8BE4C14504142A6A9050530AFF0F4836F8D1CDD57C20D689633C");
		byte[] expectedEncapsulation = Hex("044839FAFD2C4969E4A303094CE186E47A74D51497F16A12F8681735BCEB623265562AC218425A88179EDD540EFA58C1377F6043336B3DADB43EDAFEDB92BEE292");
		byte[] expectedKey = Hex("3E1933836FCBA7A48BF0092CD3B2B0F7CBA7DCC1663FF64162CF55E33BB0D4FC");
		byte[] randomKey = Hex("0C1DC49A3BFBCD716E272F3563B69369F5C78BCF6B30953325056B1BC05291F2");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ciphertext).IsEquivalentTo(expectedCiphertext, CollectionOrdering.Matching);
			await Assert.That(der.AsSpan(0, derWritten).ToArray()).IsEquivalentTo(expectedDer, CollectionOrdering.Matching);
			await Assert.That(Decrypt(key, expectedCiphertext)).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(DecryptDer(imported, expectedDer)).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(encapsulation).IsEquivalentTo(expectedEncapsulation, CollectionOrdering.Matching);
			await Assert.That(sharedKey).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(key, expectedEncapsulation, 32)).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(key, Hex("04A79E165C7558995B65A9194E9D40345F854F12D1939EAD04B7C31B829FAE269438F4A55BB67477C8893673981BEE4381F58EAD5D86B64795ED20C877C87109CB"), 32)).IsEquivalentTo(randomKey, CollectionOrdering.Matching);
			await Assert.That(() => SM9EncryptionKey.ImportPrivateKey(privateKey, publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
		}
	}

	// Key exchange keys of hid = 0x05, with QA and QB of that hid, give these keys, ephemeral keys, key and confirmations for the master key and random numbers of GM/T 0044.5, B.2, and a key of 16 bytes.
	[Test]
	public async Task KeyExchangeOfAnotherHidMatchesTheVectors()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(ExchangeMasterKey));
		using SM9KeyExchangeKey alice = master.ExtractKeyExchangeKey(Alice, OtherHid);
		byte[] bobKey = Hex("04A957B48CB7B395AD3D351CA04009487537840E759A87D73DB917049A1477093698A503CCF285E1EF16D9FAC25718B77722203B5482F8BAA1FD947934D4F5E87183D95C69F4024544F6EA74840DB5B1F2AED59E251434DBAEEA89DD876D066C661B124B400E2F24D96E6CB075CED2366721238D0FE8E2FE08D0DD4AEEDA10FBA2");
		byte[] publicKey = ExportPublicKey(master);
		using SM9KeyExchangeKey bob = SM9KeyExchangeKey.ImportPrivateKey(bobKey, publicKey, Bob, OtherHid);
		using SM9KeyExchangeKey extractedBob = master.ExtractKeyExchangeKey(Bob, OtherHid);
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
		byte[] expectedKey = Hex("5EE50530E13C16997E9D53803EE00AF5");
		byte[] confirmationA = Hex("E5552D90D92F381C3E1833E8C3C57E28163228E67DCC4371BA8B46E655D81ED3");
		byte[] confirmationB = Hex("E508D70F9E0222D052D7AE3D122E4F8D4BC77F34CB15EB5F9D724B82B63172DD");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(alice)).IsEquivalentTo(Hex("048F9DEE2987A48222AFACC9AD3567743BCEB35B92EDD7A8B7D2FDC99FCAE4A15A9372CF26041C10A661E7A64A8B0CA1C6AD0C97BE3E5BE2A4FE26E9CD856BA5BD7D310855BA008AAA3ECC8701DF283A778E2C83A923F4A524CF1DBD8FCEAD83B119C0572F4E775B5320C4FE46519DA43A1D2474177AFED36AD074457D8C832B66"), CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(bob)).IsEquivalentTo(bobKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(extractedBob)).IsEquivalentTo(bobKey, CollectionOrdering.Matching);
			await Assert.That(ephemeralA).IsEquivalentTo(Hex("04B526D785B01494C353F7C4991E60855AE431C8DDB61BE3EE1787BA97D2488D3D6149E899D211142775F9F67378E53BCFB10B502776FD60AC97C5B8775F848DB6"), CollectionOrdering.Matching);
			await Assert.That(ephemeralB).IsEquivalentTo(Hex("04919EF2D84D5D4580E5C834E4B7D5BB4C24846A02471DC2310E96EC8F9FBBCB7C8F738CE6FD64C2B185D461FB9BD66A3BFCB22DA7F01FB00117DB6DAA4052D274"), CollectionOrdering.Matching);
			await Assert.That(derivedB).IsTrue();
			await Assert.That(derivedA).IsTrue();
			await Assert.That(keyA).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(keyB).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(sA).IsEquivalentTo(confirmationA, CollectionOrdering.Matching);
			await Assert.That(s2).IsEquivalentTo(confirmationA, CollectionOrdering.Matching);
			await Assert.That(sB).IsEquivalentTo(confirmationB, CollectionOrdering.Matching);
			await Assert.That(s1).IsEquivalentTo(confirmationB, CollectionOrdering.Matching);
			await Assert.That(() => SM9KeyExchangeKey.ImportPrivateKey(bobKey, publicKey, Bob)).Throws<ArgumentException>().WithParameterName("privateKey");
		}
	}

	public static IEnumerable<Func<(string Id, string Message, string PrivateKey, string Signature)>> ExternalSignatures()
	{
		yield return () => ("Alice", "Chinese IBS standard", $"04 {SignKeyX} {SignKeyY}", "3066042097D5031DF8B3F21BF9A143501C2A1711D3964C0A25B4378FF96811B0C926AD04034200042E33EAECD03A2325187E20F51CED396FD8833263B00282CCB46A131FA18E602C03C31A085AB8ABFC9457BCACDC3698436F8E95B4144862AE965DE7A49DFA025E");
		yield return () => ("alice@example.com", "a message for CryptoBase", "0409C93BFAB338F294CCDBA024F654D5F5D396F5965CC956DFA15B285A459EFD0FB454DBA6D4191D1AF207F36F50677ACAD757DE2563F2EF579AFF6D20B8B431FB", "30660420933B18290BB0422D171AE44C6AC1302B851001D6FD29A03F73D18E2B9E49FADE03420004A561254AA61AAC02778F92974B3EAE6369B8FDBA0BC26AFEC1EEAD4AAE6A5CF4B145F538C8F38642125918B814DE2119C205E2A50E1C615F44CCABB7C2B1746A");
	}

	public static IEnumerable<Func<(string Id, string PrivateKey, string Encapsulation, string Key)>> ExternalEncapsulations()
	{
		yield return () => ("Bob", $"04 {EncryptKeyX1} {EncryptKeyX0} {EncryptKeyY1} {EncryptKeyY0}", "045417E9FAD017045D66F5BA27AD4E3D21F496C032300886BF39A118C3D642DE792D26B6475F522AD3CBE9B57BB3E16AE7295BA4E44886A1E5185B24708E372080", "324D197C0238076179D0616342702B4841D90A7267DFCEAF07F7D4AF45B67A0A");
		yield return () => ("bob@example.com", "04A7BC9809563A090F533207C78FE0521C9DA529EAC240079F06B332DCA6C2EE6D4ADD1F915728E8C2E24947E207FBB7F54740DAA01331E98207AD78ADA394AF9F48258944015557A0A09B4C0429514F5DCBDE563520138BFE56BAED576ABA8E2F3A6F638BA74E9379E31A14B47778C6E2776425637EA8DF7A8ECB9D27B5491C7E", "04B0333B8BAA6AA2F972AE2114958A723540E720B01927577E26E32D1B05C434302AEBFE7233098A74635C34DAD6BEDCBEB7EACC62B7B3D1571EF386E42C3F6271", "3A5CE31E2BCC11ACA4768B6B7E74DC91C8B92511788313B29BCAF0387597B742E22C2F6A1B1FF64405BF9EABB0D7A1AC080DF8ED039CBD221BBFAE2E324ED7CC2AF1D16C735503E4A5DFFB6D1A3865CBDBB3B5C7AAB60E64B00208FC63F983E967BDE053");
	}

	// The keys extract as the vectors give them, and the DER signatures verify, as do their h ‖ S.
	[Test]
	[MethodDataSource(nameof(ExternalSignatures))]
	public async Task ExternalSignaturesVerify(string id, string message, string privateKey, string signature)
	{
		using SM9SignatureMasterKey master = SM9SignatureMasterKey.ImportPrivateKey(Scalar(SignMasterKey));
		using SM9SignatureKey key = master.ExtractKey(Encoding.ASCII.GetBytes(id));
		using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(ExportPublicKey(master));
		byte[] der = Hex(signature);
		byte[] raw = [.. der.AsSpan(4, 32), .. der.AsSpan(39)];
		byte[] idBytes = Encoding.ASCII.GetBytes(id);
		byte[] messageBytes = Encoding.ASCII.GetBytes(message);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(Hex(privateKey), CollectionOrdering.Matching);
			await Assert.That(verifier.VerifyDer(messageBytes, der, idBytes)).IsTrue();
			await Assert.That(verifier.Verify(messageBytes, raw, idBytes)).IsTrue();
			await Assert.That(verifier.VerifyDer([.. messageBytes, 0], der, idBytes)).IsFalse();
		}
	}

	[Test]
	[MethodDataSource(nameof(ExternalEncapsulations))]
	public async Task ExternalEncapsulationsDecapsulate(string id, string privateKey, string encapsulation, string key)
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey));
		using SM9EncryptionKey user = master.ExtractKey(Encoding.ASCII.GetBytes(id));
		byte[] expected = Hex(key);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(user)).IsEquivalentTo(Hex(privateKey), CollectionOrdering.Matching);
			await Assert.That(Decapsulate(user, Hex(encapsulation), expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	// An SM9Cipher whose C3 is HMAC-SM3 with the key K2 rather than MAC(K2, C2) = SM3(C2 ‖ K2) of GM/T 0044.4, Sec. 5.4.5, which GM/T 0044.5, D.2, takes, does not decrypt, though its C1 and C2 follow GM/T 0044.4.
	[Test]
	public async Task CiphertextsWithAnHmacC3DoNotDecrypt()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(EncryptMasterKey));
		using SM9EncryptionKey user = master.ExtractKey(Bob);
		byte[] ciphertext = Hex("307F020100034200049C5E251DD0E467FFACED74936CD659E2AA14B19834704C14337DB7796B3F1C4A9AE421ED99900AA873801C74DCF373BC3A58DEC5DF281E2C7D7ACA123663F9C104202774A383C976B36541E7E8FD1D175DC6F34FBD3A78A6ACCA4E255030AAD171D50414808F790CA6FAB720E191C6CF3428DA1CD0C5FC01");
		byte[] message = "Chinese IBE standard"u8.ToArray();
		AsnReader sequence = new AsnReader(ciphertext, AsnEncodingRules.DER).ReadSequence();
		int enType = (int)sequence.ReadInteger();
		byte[] c1 = sequence.ReadBitString(out int unusedBits);
		byte[] c3 = sequence.ReadOctetString();
		byte[] c2 = sequence.ReadOctetString();
		byte[] k = Decapsulate(user, c1, c2.Length + 32)!;
		byte[] hmac = new byte[32];
		HmacAlgorithm<SM3Core>.Mac(k.AsSpan(c2.Length), c2, hmac);

		using (Assert.Multiple())
		{
			await Assert.That(enType).IsZero();
			await Assert.That(unusedBits).IsZero();
			await Assert.That(c2.Zip(k, static (c, key) => (byte)(c ^ key))).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(hmac).IsEquivalentTo(c3, CollectionOrdering.Matching);
			await Assert.That(Sm3(c2, k.AsSpan(c2.Length).ToArray())).IsNotEquivalentTo(c3);
			await Assert.That(DecryptDer(user, ciphertext)).IsNull();
		}
	}

	// Key exchange keys of hid = 0x02, with QA and QB of that hid, give this key and these confirmations for the master key and random numbers of GM/T 0044.5, B.2, and a key of 16 bytes.
	[Test]
	public async Task KeyExchangeMatchesTheVectors()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.ImportPrivateKey(Scalar(ExchangeMasterKey));
		using SM9KeyExchangeKey alice = master.ExtractKeyExchangeKey(Alice);
		using SM9KeyExchangeKey bob = master.ExtractKeyExchangeKey(Bob);
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
		byte[] expectedKey = Hex("C5C13A8F59A97CDEAE64F16A2272A9E7");
		byte[] expectedSA = Hex("195D1B7256BA7E0E67C71202A25F8C94FF8241702C2F55D613AE1C6B98215172");
		byte[] expectedSB = Hex("3BB4BCEE8139C960B4D6566DB1E0D5F0B2767680E5E1BF934103E6C66E40FFEE");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(alice)).IsEquivalentTo(Hex("040FE8EAB395199B56BF1D75BD2CD610B6424F08D1092922C5882B52DCD6CA832A7DA57BC50241F9E5BFDDC075DD9D32C7777100D736916CFC165D8D36E0634CD783A457DAF52CAD464C903B26062CAF937BB40E37DADED9EDA401050E49C8AD0C6970876B9AAD1B7A50BB4863A11E574AF1FE3C5975161D73DE4C3AF621FB1EFB"), CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(bob)).IsEquivalentTo(Hex("0474CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF701092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B244B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC18CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539"), CollectionOrdering.Matching);
			await Assert.That(ephemeralA).IsEquivalentTo(Hex("047CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599"), CollectionOrdering.Matching);
			await Assert.That(ephemeralB).IsEquivalentTo(Hex("04861E91485FB7623D2794F495031A35598B493BD45BE37813ABC710FCC1F3448232D906A469EBC1216A802A7052D5617CD430FB56FBA729D41D9BD668E9EB9600"), CollectionOrdering.Matching);
			await Assert.That(derivedB).IsTrue();
			await Assert.That(derivedA).IsTrue();
			await Assert.That(keyA).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(keyB).IsEquivalentTo(expectedKey, CollectionOrdering.Matching);
			await Assert.That(sA).IsEquivalentTo(expectedSA, CollectionOrdering.Matching);
			await Assert.That(s2).IsEquivalentTo(expectedSA, CollectionOrdering.Matching);
			await Assert.That(sB).IsEquivalentTo(expectedSB, CollectionOrdering.Matching);
			await Assert.That(s1).IsEquivalentTo(expectedSB, CollectionOrdering.Matching);
		}
	}
}
