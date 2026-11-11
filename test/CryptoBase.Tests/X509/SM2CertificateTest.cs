using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.SM2;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// SM2 certificates with the default ID "1234567812345678" of GB/T 35276-2017.
//
// The files of X509/SM2 that start with sm2- are a chain valid from 2026-01-01 to 2036-01-01: sm2-root.pem, sm2-intermediate.pem and sm2-leaf.pem,
// signed with the default ID, and sm2-leaf-empty-id.pem, a leaf of the same key that the intermediate signed with the empty ID.
//
// nrcac-root.pem is the self-signed root C=CN, O=NRCAC, CN=ROOTCA of 2012 (SHA-256 fingerprint
// 9C28D3847414BFFF1A5749E7E2381146F82842083E8C592E16A612D04A5BA8CD), whose SM2-with-SM3 identifiers have NULL parameters.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class SM2CertificateTest
{
	private const string SM2SM3Oid = "1.2.156.10197.1.501";
	private const string ECPublicKeyOid = "1.2.840.10045.2.1";
	private const string SM2CurveOid = "1.2.156.10197.1.301";

	private static readonly DateTimeOffset ValidTime = new(2027, 1, 1, 0, 0, 0, TimeSpan.Zero);

	private static Certificate Root => Read("sm2-root.pem");

	private static Certificate Intermediate => Read("sm2-intermediate.pem");

	private static Certificate Leaf => Read("sm2-leaf.pem");

	private static Certificate EmptyIdLeaf => Read("sm2-leaf-empty-id.pem");

	[Test]
	public async Task VerifiesTheChainFiles()
	{
		Certificate root = Root;
		Certificate intermediate = Intermediate;
		Certificate leaf = Leaf;
		using ISignatureKey rootKey = SignatureKey.ImportSubjectPublicKeyInfo(root.PublicKeyInfo.Encoded.Span);
		using ISignatureKey intermediateKey = SignatureKey.ImportSubjectPublicKeyInfo(intermediate.PublicKeyInfo.Encoded.Span);
		using EcdsaP256 ecdsa = EcdsaP256.GenerateKey();
		byte[] identifier = AlgorithmIdentifier.FromSignatureAlgorithm(SignatureAlgorithm.SM2SM3).Encoded.ToArray();

		using (Assert.Multiple())
		{
			foreach (Certificate certificate in (Certificate[])[root, intermediate, leaf, EmptyIdLeaf])
			{
				await Assert.That(certificate.SignatureAlgorithm.Encoded).IsEquivalentTo(identifier, CollectionOrdering.Matching);
				await Assert.That(certificate.PublicKeyInfo.Algorithm.Oid).IsEqualTo(ECPublicKeyOid);
				await Assert.That(certificate.PublicKeyInfo.Algorithm.Parameters).IsEquivalentTo(Oid(SM2CurveOid), CollectionOrdering.Matching);
			}

			await Assert.That(rootKey.GetType()).IsEqualTo(typeof(SM2Key));
			await Assert.That(root.VerifySignature(rootKey)).IsTrue();
			await Assert.That(intermediate.VerifySignature(rootKey)).IsTrue();
			await Assert.That(leaf.VerifySignature(intermediateKey)).IsTrue();
			await Assert.That(leaf.VerifySignature(rootKey)).IsFalse();
			await Assert.That(leaf.VerifySignature(ecdsa)).IsFalse();
			await Assert.That(Tamper(leaf).VerifySignature(intermediateKey)).IsFalse();
		}
	}

	// A signature with the empty ID fails SM2SM3; it is valid with that ID.
	[Test]
	public async Task RejectsASignatureWithAnotherId()
	{
		Certificate leaf = EmptyIdLeaf;
		using SM2Key intermediateKey = SM2Key.ImportSubjectPublicKeyInfo(Intermediate.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(leaf.VerifySignature(intermediateKey)).IsFalse();
			await Assert.That(intermediateKey.Verify(leaf.TbsCertificate.Span, leaf.Signature.Span, [])).IsTrue();
		}
	}

	// GM/T 0015-2012 gives NULL parameters, which this root has; its signature has the default ID.
	[Test]
	public async Task VerifiesARootWithNullParameters()
	{
		Certificate root = Read("nrcac-root.pem");
		using ISignatureKey key = SignatureKey.ImportSubjectPublicKeyInfo(root.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(root.SignatureAlgorithm.Oid).IsEqualTo(SM2SM3Oid);
			await Assert.That(root.SignatureAlgorithm.Parameters).IsEquivalentTo((byte[])[0x05, 0x00], CollectionOrdering.Matching);
			await Assert.That(root.SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm) ? algorithm : default).IsEqualTo(SignatureAlgorithm.SM2SM3);
			await Assert.That(key.GetType()).IsEqualTo(typeof(SM2Key));
			await Assert.That(root.VerifySignature(key)).IsTrue();
			await Assert.That(Tamper(root).VerifySignature(key)).IsFalse();
		}
	}

	[Test]
	public async Task ValidatesTheChainFiles()
	{
		Certificate root = Root;
		Certificate intermediate = Intermediate;
		Certificate leaf = Leaf;
		Certificate emptyId = EmptyIdLeaf;
		Certificate tampered = Tamper(leaf);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root], [leaf, intermediate], hostName: "example.com", time: ValidTime), leaf, intermediate, root);
			await AssertValid(await Validate([intermediate], [leaf], hostName: "example.com", time: ValidTime), leaf, intermediate);
			await AssertInvalid(await Validate([root], [emptyId, intermediate], time: ValidTime), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, emptyId, intermediate, root);
			await AssertInvalid(await Validate([root], [tampered, intermediate], time: ValidTime), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, tampered, intermediate, root);
		}
	}

	// A root that CertificateBuilder signs issues with SM2 and SM3, its identifier with or without NULL parameters, and with the default ID only.
	[Test]
	public async Task ValidatesChainsOfCertificateBuilder()
	{
		using Authority root = CreateRoot();
		using SM2Key leafKey = SM2Key.GenerateKey();
		Template template = new() { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(leafKey), Extensions = [SubjectAlternativeNames("example.com"), AuthorityKeyIdentifier(root.KeyIdentifier)] };
		Certificate leaf = root.Issue(template);
		Certificate withNull = Sign(template, root.Name, Sequence(Oid(SM2SM3Oid), [0x05, 0x00]), tbs => Sign(root.Key, SignatureAlgorithm.SM2SM3, tbs));
		Certificate otherId = Sign(template, root.Name, AlgorithmIdentifier.FromSignatureAlgorithm(SignatureAlgorithm.SM2SM3).Encoded.ToArray(), tbs => SignWithId((SM2Key)root.Key, tbs, "ALICE123@YAHOO.COM"));
		Certificate tampered = Tamper(leaf);

		using (Assert.Multiple())
		{
			await Assert.That(root.Certificate.VerifySignature(root.Key)).IsTrue();
			await AssertValid(await Validate([root.Certificate], [leaf], hostName: "example.com"), leaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [withNull], hostName: "example.com"), withNull, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [otherId]), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, otherId, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [tampered]), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, tampered, root.Certificate);
		}
	}

	// An SM2 signature does not verify with an ECDSA key, nor an ECDSA signature with an SM2 key; an SM2 key with other parameters, or an SM2 point named as one on P-256, does not import.
	[Test]
	public async Task RejectsKeysOnOtherCurveParameters()
	{
		using Authority root = CreateRoot();
		using Authority ecdsaRoot = Authority.CreateRoot("CN=ECDSA Root");
		using SM2Key intermediateKey = SM2Key.GenerateKey();
		byte[] point = new byte[SM2Key.PublicKeyLength];
		intermediateKey.ExportPublicKey(point);
		byte[] onP256 = Sequence(Sequence(Oid(ECPublicKeyOid), Oid("1.2.840.10045.3.1.7")), Tlv(0x03, [0x00, .. point]));
		byte[] curveAsAlgorithm = Sequence(Sequence(Oid(SM2CurveOid)), Tlv(0x03, [0x00, .. point]));
		byte[] explicitCurve = Sequence(Sequence(Oid(ECPublicKeyOid), Sequence([0x02, 0x01, 0x01])), Tlv(0x03, [0x00, .. point]));
		Certificate signedBySM2 = root.IssueLeaf();
		Certificate signedByEcdsa = ecdsaRoot.IssueLeaf();
		using ISignatureKey ecdsaKey = SignatureKey.ImportSubjectPublicKeyInfo(ecdsaRoot.Certificate.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(signedBySM2.VerifySignature(ecdsaKey)).IsFalse();
			await Assert.That(signedByEcdsa.VerifySignature(root.Key)).IsFalse();
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(onP256)).ThrowsExactly<ArgumentException>();
			await AssertIntermediateKey(root, intermediateKey, onP256, CertificateValidationError.Malformed);
			await AssertIntermediateKey(root, intermediateKey, curveAsAlgorithm, CertificateValidationError.UnsupportedAlgorithm);
			await AssertIntermediateKey(root, intermediateKey, explicitCurve, CertificateValidationError.UnsupportedAlgorithm);
			await AssertIntermediateKey(root, intermediateKey, ExportSubjectPublicKeyInfo(intermediateKey), null);
		}
	}

	// A self-signed SM2 root with the extensions of a CA, which issues with SM2 and SM3.
	private static Authority CreateRoot()
	{
		SM2Key key = SM2Key.GenerateKey();
		byte[] name = Name("CN=SM2 Root");
		CertificateBuilder builder = new(name);

		foreach (CertificateExtension extension in CaExtensions(ExportSubjectPublicKeyInfo(key)))
		{
			builder.Extensions.Add(extension);
		}

		return new Authority(name, key, builder.CreateSelfSigned(key, SignatureAlgorithm.SM2SM3, Now.AddDays(-1), Now.AddDays(30)), SignatureAlgorithm.SM2SM3);
	}

	// An intermediate CA with the subject public key info given, which root signs, issues a leaf with key; the path fails with error, or is valid without one.
	private static async Task AssertIntermediateKey(Authority root, SM2Key key, byte[] subjectPublicKeyInfo, CertificateValidationError? error)
	{
		byte[] name = Name("CN=SM2 Intermediate");
		Certificate intermediate = root.Issue(new Template { Subject = name, SubjectPublicKeyInfo = subjectPublicKeyInfo, Extensions = [BasicConstraints(true), KeyUsage(X509KeyUsageFlags.KeyCertSign)] });
		Certificate leaf = new Authority(name, key, intermediate, SignatureAlgorithm.SM2SM3).IssueLeaf();
		CertificateValidationResult result = await Validate([root.Certificate], [leaf, intermediate]);

		if (error is { } expected)
		{
			await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, Convert.ToHexString(subjectPublicKeyInfo), [leaf, intermediate, root.Certificate]);
		}
		else
		{
			await AssertValid(result, leaf, intermediate, root.Certificate);
		}
	}

	private static byte[] SignWithId(SM2Key key, byte[] message, string id)
	{
		byte[] signature = new byte[SM2Key.MaxSignatureLength];
		return signature.AsSpan(0, key.Sign(message, signature, Encoding.ASCII.GetBytes(id))).ToArray();
	}

	// The certificate with the last byte of its signature changed.
	private static Certificate Tamper(Certificate certificate)
	{
		byte[] encoded = certificate.Encoded.ToArray();
		encoded[^1] ^= 0x01;
		return Certificate.Decode(encoded);
	}

	private static Certificate Read(string file)
	{
		using Stream stream = typeof(SM2CertificateTest).Assembly.GetManifestResourceStream(file) ?? throw new FileNotFoundException($"The certificate '{file}' is not embedded.", file);
		using StreamReader reader = new(stream);
		return Certificate.DecodePem(reader.ReadToEnd());
	}
}
