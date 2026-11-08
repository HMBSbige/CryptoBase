using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.SM2;
using System.Security.Cryptography;
using static CryptoBase.Tests.SM2.SM2TestUtils;

namespace CryptoBase.Tests.SM2;

// Known-answer vectors, checked both ways: a key, signatures of "message" with the default ID, with ALICE123@YAHOO.COM and with the empty ID, and SM2Cipher ciphertexts,
// and the ciphertext that the key writes below from a fixed nonce.
public class SM2InteropTest
{
	private static readonly byte[] Pkcs8PrivateKey = Hex("308187020100301306072A8648CE3D020106082A811CCF5501822D046D306B0201010420FF43D8DAF6177147291CF12497B160B008BC941A90B2A1DC3E3D596CF5BC95AEA144034200046F3E8899A89B90ED470106D684468D2D4A2124B70F1BB880D27FCFB3101DF0F001A54CD9063C0F8026A90B69D2DB9AD040AC27BECE601021B54F909847A7FEC7");

	private static readonly byte[] SubjectPublicKeyInfo = Hex("3059301306072A8648CE3D020106082A811CCF5501822D034200046F3E8899A89B90ED470106D684468D2D4A2124B70F1BB880D27FCFB3101DF0F001A54CD9063C0F8026A90B69D2DB9AD040AC27BECE601021B54F909847A7FEC7");

	// An ECPrivateKey with the curve and the public key, as an EC PRIVATE KEY or SM2 PRIVATE KEY block holds it.
	private static readonly byte[] ECPrivateKey = Hex("30770201010420FF43D8DAF6177147291CF12497B160B008BC941A90B2A1DC3E3D596CF5BC95AEA00A06082A811CCF5501822DA144034200046F3E8899A89B90ED470106D684468D2D4A2124B70F1BB880D27FCFB3101DF0F001A54CD9063C0F8026A90B69D2DB9AD040AC27BECE601021B54F909847A7FEC7");

	private static readonly byte[] Message = "message"u8.ToArray();

	private static readonly byte[] AliceId = "ALICE123@YAHOO.COM"u8.ToArray();

	[Test]
	public async Task ExternalKeysImport()
	{
		using SM2Key fromPkcs8 = SM2Key.ImportPkcs8PrivateKey(Pkcs8PrivateKey);
		using SM2Key fromSpki = SM2Key.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo);
		using ISignatureKey fromPem = SignatureKey.ImportFromPem(PemEncoding.WriteString("EC PRIVATE KEY", ECPrivateKey));
		using ISignatureKey fromSM2Pem = SignatureKey.ImportFromPem(PemEncoding.WriteString("SM2 PRIVATE KEY", ECPrivateKey));
		using ISignatureKey fromPkcs8Pem = SignatureKey.ImportFromPem(PemEncoding.WriteString("PRIVATE KEY", Pkcs8PrivateKey));
		byte[] privateKey = new byte[SM2Key.PrivateKeyLength];
		fromPkcs8.ExportPrivateKey(privateKey);

		using (Assert.Multiple())
		{
			await Assert.That(privateKey).IsEquivalentTo(Hex("FF43D8DAF6177147291CF12497B160B008BC941A90B2A1DC3E3D596CF5BC95AE"), CollectionOrdering.Matching);
			await Assert.That(fromPem).IsTypeOf<SM2Key>();
			await Assert.That(fromSM2Pem).IsTypeOf<SM2Key>();
			await Assert.That(fromPkcs8Pem).IsTypeOf<SM2Key>();

			foreach (ISignatureKey key in (ISignatureKey[])[fromPkcs8, fromSpki, fromPem, fromSM2Pem, fromPkcs8Pem])
			{
				byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
				key.ExportSubjectPublicKeyInfo(spki);
				await Assert.That(spki).IsEquivalentTo(SubjectPublicKeyInfo, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task ExternalSignaturesVerifyWithTheirIds()
	{
		using SM2Key key = SM2Key.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo);
		byte[] withDefaultId = Hex("304402205FFF8731A6D48EE1D5771112D1BCEEA553C06D1F25D5C85F58F80A9B2C8C799902204634068EE53223F817166F82A08EF59171254D81E7A763B2DB9EE78E71CB1B3B");
		byte[] withEmptyId = Hex("3046022100CAC22F028C588D08B85DE159BEAF88A17B65C86EF8918614C4E2B2561C6D61D4022100B83DF99CDECE0452DE79FE675722B91A4AFDDA73634357D46361A8CBD6E95775");
		byte[] withAliceId = Hex("3045022100E1553DA74B4C7C51FA719CE693BCE18EEB6532B802190A770AA2F8D48F64F4A90220789624622E1038142FA4EF560ECC9590317549335F3A6E79849B433546240EEE");

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(Message, withDefaultId)).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.SM2SM3, Message, withDefaultId)).IsTrue();
			await Assert.That(key.Verify(Message, withEmptyId, [])).IsTrue();
			await Assert.That(key.Verify(Message, withAliceId, AliceId)).IsTrue();
			await Assert.That(key.Verify(Message, withEmptyId)).IsFalse();
			await Assert.That(key.Verify(Message, withDefaultId, [])).IsFalse();
			await Assert.That(key.Verify(Message, withAliceId)).IsFalse();
		}
	}

	[Test]
	public async Task ExternalCiphertextsDecrypt()
	{
		using SM2Key key = SM2Key.ImportPkcs8PrivateKey(Pkcs8PrivateKey);
		(byte[] Plaintext, byte[] Ciphertext)[] vectors =
		[
			("The quick brown fox jumps over the lazy dog."u8.ToArray(), Hex("308196022100B64D7D5547F640DA6DB47C688A0B470F5E5D9C694D25DDC81B578A150882941B022100BCC680F875E1DC51938CCA2C05022A9352570EC126602ED3D46253D8D309D14C0420C2AC52743BCD8CD39EBC61B55AA2CE5796188FC1AB8BB7A86282BC879C7C32C1042C540A0EABD284F9CB5E16ADE8B44D28209088179673FE86524CAE05713C568EA88D01FDDC91E3810595A81AEF")),
			("x"u8.ToArray(), Hex("3069022063B6C6D7A6D23125FAF7113240019FDF12198F5D79E8BF201C7624040EDD795F022043AD6B76A357406BBB91CB043AE5D50A416258C3DA3B440653362637ED19C05D042094A939217E9A948C6EFACD0D747115A575D1746E87CFF7927F82A5F5FCFF2EE8040103")),
			(Hex("3E2F487FA972CCB3A32E491B00C7C427B08484C182F95CF1C19D75A2E07B7B15FE69BBF2AF91AEF49988884246757F2FD5549B9585371A564151147BD7E9F8FC1A067BEF5D797E93164ACCB4BB4D1A15EC98AC67959F02D5BA404FBBFE16EFFF323018A96AB1BFFAB3090420E29553D90513824D09296477E6A20CF9ECD3A1ABED603A0E80010D3CD376283A20FCF93BF41E0063F8FD31E2BD26EB0BDD5B551863DD416B64A964B177A674B178F4D270576CA0A06A1CBDB94B5EF5DFF474CFD4BBCE613A88F625A7"), Hex("30820133022100ED12DAFA5455EC9E02246BC64CCF87C51004368179344E3E61320D9569CE730B0221008BB97B887A37B5204D3C66B6882C5036338BDB11323DF7781D017097C899BCCB0420AF7CCD258A34AB7F51359407E488B11AF77DFDBEAE015982FA608FAA3FE33AA60481C8ABC88E2E259AA5915D41DA35853C1C3EFC1C026B4F42A2099DC884AB725C6E5135F1E00AF0EC220B5F5FC4465279747E73255E31F2DF6F183166F3031F0F0C747CDF70F851D274F94C919C706CA925A1AE5D53C9C91500CCF0D6E7E38A84DEB8BB933F0875A8A3988D9D341A0D40E3A4E93CC941F4768534BADB8830B8F3F3ED185E164325CE837B8F417D641ACFE7FA3F6498AF51B406C9E788A04DA919BB0234A7E971137621976C2CCA3294E6495656C88A5191666FFB500A844333C38224EA031C20636DD99B")),
		];

		using (Assert.Multiple())
		{
			foreach ((byte[] plaintext, byte[] ciphertext) in vectors)
			{
				await Assert.That(DecryptDer(key, ciphertext)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			}
		}
	}

	// With empty additional data the nonce follows from the key and the hash alone, so the signatures are fixed.
	[Test]
	public async Task SignaturesFromFixedNoncesMatch()
	{
		using SM2Key key = SM2Key.ImportPkcs8PrivateKey(Pkcs8PrivateKey);
		(byte[] Id, byte[] Signature)[] vectors =
		[
			(SM2Key.DefaultId.ToArray(), Hex("30450220062842D1893A0A64FAF683F437456C642DE09B98B62A203DC6CDEDB2B825EA78022100D5CC4F6A83C21390938EE21948AF83E221E4633830FDF847AC04B2F78D3D421F")),
			(AliceId, Hex("3046022100F7A1F9425D6DD9DBD7A873AC6ADE514682B7FE381A4BF2D9BA578508E2061E86022100DF6C5723795C2F71953B7FA4E09F8F3C4335E10AB2F24630BD77FDD9636CC6F7")),
			([], Hex("3045022100D1B252C49C889B2F39C884D3C9599B519C9DBDF772367443F2ABEAABF17DF6A7022038F222ED8736E49BC8C09733D161F00B1796678286E66E360D8A91EEA3ECFB0B")),
		];

		using (Assert.Multiple())
		{
			foreach ((byte[] id, byte[] expected) in vectors)
			{
				byte[] signature = new byte[SM2Key.MaxSignatureLength];
				int written = key.GetState().Sign(Message, id, [], signature);
				await Assert.That(signature.AsSpan(0, written).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task CiphertextFromAFixedNonceMatches()
	{
		using SM2Key key = SM2Key.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo);
		byte[] plaintext = "Encrypted to SM2 by CryptoBase."u8.ToArray();
		byte[] ciphertext = new byte[SM2Key.GetMaxDerCiphertextLength(plaintext.Length)];
		int written = key.EncryptDer(plaintext, ciphertext, Fill(Sm3("CryptoBase SM2 interop nonce"u8.ToArray())));

		await Assert.That(ciphertext.AsSpan(0, written).ToArray()).IsEquivalentTo(Hex("30818802205A42F8941ED3F69F89CB075FE2335EF2598C1FD07C761BC83711862704847041022100BB23A06C2EAC6EAD9FD231D91F14FD1A7C08FFA06632749DD6A7BFEBA89716540420BCB3A07A5CB32DB9897EF39F513228E927E9AD60BE48EBE53B42DC6A0F3C26D8041FD583B4AA073DBA56FE92E103BC623082E7BF72619DFB978BFEEF9849777E92"), CollectionOrdering.Matching);
	}
}
