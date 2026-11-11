#pragma warning disable SYSLIB5006

using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.SM2;
using CryptoBase.Tests.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;
using BclMLDsa = System.Security.Cryptography.MLDsa;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
internal class CertificationRequestTest
{
	private const string ExtensionRequestOid = "1.2.840.113549.1.9.14";
	private const string ChallengePasswordOid = "1.2.840.113549.1.9.7";
	private const string SubjectAlternativeNameOid = "2.5.29.17";
	private const string BasicConstraintsOid = "2.5.29.19";
	private const string KeyUsageOid = "2.5.29.15";

	private static readonly Asn1Tag AttributesTag = new(TagClass.ContextSpecific, 0, true);

	// A request whose subject, public key and extensions the builder writes and decoding returns, for every signature algorithm; the platform reads its fields and the signature covers the CertificationRequestInfo alone.
	[Test]
	[MethodDataSource(typeof(CertificateBuilderTest), nameof(CertificateBuilderTest.SigningCases))]
	public async Task CreatesRequestsThatTheBclReads(KeyType type, SignatureAlgorithm algorithm)
	{
		using ISignatureKey key = type.GenerateKey();
		byte[] name = Name("CN=Request, O=CryptoBase");
		byte[] subjectAlternativeName = SubjectAlternativeName("request.example").RawData;
		CertificationRequestBuilder builder = new(name);
		builder.Extensions.Add(new CertificateExtension(SubjectAlternativeNameOid, false, subjectAlternativeName));
		builder.Extensions.Add(new CertificateExtension(BasicConstraintsOid, true, [0x30, 0x00]));

		CertificationRequest request = builder.Create(key, algorithm);
		CertificationRequest decoded = CertificationRequest.Decode(request.Encoded.Span);
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(decoded.PublicKeyInfo.Encoded.Span);
		CertificateRequestLoadOptions options = CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions | (BclVerifies(algorithm) ? CertificateRequestLoadOptions.Default : CertificateRequestLoadOptions.SkipSignatureValidation);
		CertificateRequest loaded = CertificateRequest.LoadSigningRequest(decoded.Encoded.ToArray(), HashAlgorithmName.SHA256, options);

		using (Assert.Multiple())
		{
			await Assert.That(builder.SubjectName).IsEquivalentTo(name, CollectionOrdering.Matching);
			await Assert.That(decoded.Subject).IsEquivalentTo(name, CollectionOrdering.Matching);
			await Assert.That(decoded.PublicKeyInfo.Encoded).IsEquivalentTo(ExportSubjectPublicKeyInfo(key), CollectionOrdering.Matching);
			await Assert.That(decoded.SignatureAlgorithm.Encoded).IsEquivalentTo(AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(decoded.RequestedExtensions.Select(static extension => (extension.Oid, extension.Critical, Convert.ToHexString(extension.Value.Span)))).IsEquivalentTo([(SubjectAlternativeNameOid, false, Convert.ToHexString(subjectAlternativeName)), (BasicConstraintsOid, true, "3000")], CollectionOrdering.Matching);
			await Assert.That(decoded.VerifySignature(key)).IsTrue();
			await Assert.That(decoded.VerifySignature(publicKey)).IsTrue();
			await Assert.That(key.Verify(algorithm, decoded.CertificationRequestInfo.Span, decoded.Signature.Span)).IsTrue();
			await Assert.That(CertificationRequest.Decode(FlipSignature(decoded)).VerifySignature(publicKey)).IsFalse();
			await Assert.That(loaded.SubjectName.RawData).IsEquivalentTo(name, CollectionOrdering.Matching);
			await Assert.That(loaded.PublicKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(decoded.PublicKeyInfo.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(loaded.CertificateExtensions.Select(static extension => (extension.Oid?.Value ?? "", extension.Critical, Convert.ToHexString(extension.RawData)))).IsEquivalentTo([(SubjectAlternativeNameOid, false, Convert.ToHexString(subjectAlternativeName)), (BasicConstraintsOid, true, "3000")], CollectionOrdering.Matching);
		}
	}

	// The platform verifies the signature when it loads a request, so a changed signature must make it throw.
	[Test]
	[MethodDataSource(nameof(BclVerifiedAlgorithms))]
	public async Task TheBclVerifiesRequests(KeyType type, SignatureAlgorithm algorithm)
	{
		using ISignatureKey key = type.GenerateKey();
		CertificationRequest request = new CertificationRequestBuilder(Name("CN=Verified")).Create(key, algorithm);
		byte[] tampered = FlipSignature(request);

		using (Assert.Multiple())
		{
			await Assert.That(() => CertificateRequest.LoadSigningRequest(request.Encoded.ToArray(), HashAlgorithmName.SHA256)).ThrowsNothing();
			await Assert.That(() => CertificateRequest.LoadSigningRequest(tampered, HashAlgorithmName.SHA256)).Throws<CryptographicException>();
		}
	}

	public static IEnumerable<Func<(KeyType Type, SignatureAlgorithm Algorithm)>> BclVerifiedAlgorithms()
	{
		foreach (KeyType type in KeyTypes)
		{
			foreach (SignatureAlgorithm algorithm in type.Algorithms)
			{
				if (BclVerifies(algorithm))
				{
					yield return () => (type, algorithm);
				}
			}
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DecodesBclEcdsaRequests([Matrix(256, 384, 521)] int curveBits, [Matrix(SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.EcdsaSha384, SignatureAlgorithm.EcdsaSha512)] SignatureAlgorithm algorithm)
	{
		using ECDsa key = ECDsa.Create(EcdsaCurve(curveBits).Curve);

		await AssertDecodesBclRequest(new CertificateRequest("CN=Platform ECDSA", key, EcdsaTestUtils.HashName(algorithm)), algorithm);
	}

	[Test]
	[MethodDataSource(nameof(RsaAlgorithmCases))]
	public async Task DecodesBclRsaRequests(SignatureAlgorithm algorithm)
	{
		using RSA key = CreateRsa();
		(HashAlgorithmName hash, RSASignaturePadding padding) = RsaParametersOf(algorithm);

		await AssertDecodesBclRequest(new CertificateRequest("CN=Platform RSA", key, hash, padding), algorithm);
	}

	[Test]
	[Arguments(SignatureAlgorithm.MLDsa44)]
	[Arguments(SignatureAlgorithm.MLDsa65)]
	[Arguments(SignatureAlgorithm.MLDsa87)]
	public async Task DecodesBclMLDsaRequests(SignatureAlgorithm algorithm)
	{
		Skip.Unless(BclMLDsa.IsSupported, "The platform does not support ML-DSA.");

		MLDsaAlgorithm bclAlgorithm = algorithm switch
		{
			SignatureAlgorithm.MLDsa44 => MLDsaAlgorithm.MLDsa44,
			SignatureAlgorithm.MLDsa65 => MLDsaAlgorithm.MLDsa65,
			_ => MLDsaAlgorithm.MLDsa87
		};
		using BclMLDsa key = BclMLDsa.GenerateKey(bclAlgorithm);

		await AssertDecodesBclRequest(new CertificateRequest("CN=Platform ML-DSA", key), algorithm);
	}

	// The platform has no Ed25519, Ed448 or SM2, so it builds the request around a signature of the CryptoBase key through a signature generator.
	[Test]
	[Arguments(typeof(Ed25519), SignatureAlgorithm.Ed25519)]
	[Arguments(typeof(Ed448), SignatureAlgorithm.Ed448)]
	[Arguments(typeof(SM2Key), SignatureAlgorithm.SM2SM3)]
	public async Task DecodesRequestsThatTheBclBuildsAroundAGenerator(Type keyType, SignatureAlgorithm algorithm)
	{
		using ISignatureKey key = KeyTypes.First(type => type.Type == keyType).GenerateKey();
		KeySignatureGenerator generator = new(key, algorithm);
		CertificateRequest request = new(new X500DistinguishedName("CN=Generator"), generator.PublicKey, HashAlgorithmName.SHA256);
		request.CertificateExtensions.Add(SubjectAlternativeName("bcl.example"));

		CertificationRequest decoded = CertificationRequest.Decode(request.CreateSigningRequest(generator));
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(decoded.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.VerifySignature(publicKey)).IsTrue();
			await Assert.That(decoded.RequestedExtensions.Select(static extension => extension.Oid)).IsEquivalentTo([SubjectAlternativeNameOid], CollectionOrdering.Matching);
		}
	}

	// RFC 2986, Sec. 4.1: attributes need only be present, and other attributes than extensionRequest are left alone, in any number of values.
	[Test]
	public async Task AcceptsTheValidFormsOfAttributes()
	{
		byte[] password = Tlv(0x0C, "secret"u8.ToArray());
		byte[] extensionRequest = Attribute(ExtensionRequestOid, Sequence(Extension(BasicConstraintsOid, [0x30, 0x00])));
		RequestParts parts = new();

		CertificationRequest empty = CertificationRequest.Decode(parts.Encode());
		CertificationRequest other = CertificationRequest.Decode((parts with { Attributes = AttributeSet(Attribute(ChallengePasswordOid, password)) }).Encode());
		CertificationRequest multiple = CertificationRequest.Decode((parts with { Attributes = AttributeSet(Attribute("1.2.3.4", [0x05, 0x00], [0x02, 0x01, 0x01])) }).Encode());
		CertificationRequest both = CertificationRequest.Decode((parts with { Attributes = AttributeSet(Attribute(ChallengePasswordOid, password), extensionRequest) }).Encode());
		CertificationRequest noSubject = CertificationRequest.Decode((parts with { Subject = Sequence() }).Encode());
		CertificationRequest trailingKeyUsageBits = CertificationRequest.Decode((parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, Sequence(Extension(KeyUsageOid, [0x03, 0x02, 0x00, 0x80])))) }).Encode());

		using (Assert.Multiple())
		{
			await Assert.That(empty.RequestedExtensions).IsEmpty();
			await Assert.That(other.RequestedExtensions).IsEmpty();
			await Assert.That(multiple.RequestedExtensions).IsEmpty();
			await Assert.That(both.RequestedExtensions.Select(static extension => extension.Oid)).IsEquivalentTo([BasicConstraintsOid], CollectionOrdering.Matching);
			await Assert.That(noSubject.Subject).IsEquivalentTo(Sequence(), CollectionOrdering.Matching);
			await Assert.That(trailingKeyUsageBits.RequestedExtensions.Count).IsEqualTo(1);
		}
	}

	public static IEnumerable<Func<(string Reason, byte[] Encoded)>> MalformedRequests()
	{
		RequestParts parts = new();
		byte[] encoded = parts.Encode();
		byte[] smaller = Attribute("1.2.3", [0x05, 0x00]);
		byte[] larger = Attribute(ChallengePasswordOid, Tlv(0x0C, "x"u8.ToArray()));
		byte[] extensions = Sequence(Extension(BasicConstraintsOid, [0x30, 0x00]));
		byte[] otherExtensions = Sequence(Extension(KeyUsageOid, [0x03, 0x02, 0x07, 0x80]));

		(string, byte[])[] cases =
		[
			("empty", []),
			("truncated", encoded.AsSpan(0, encoded.Length - 1).ToArray()),
			("trailing garbage", [.. encoded, 0x00]),
			("outer tag", Tlv(0x31, Contents(encoded))),
			("redundant outer length byte", WithRedundantLengthByte(encoded)),
			("field after the signature", Sequence(parts.Info(), parts.SignatureAlgorithm, parts.Signature, [0x05, 0x00])),
			("field after the attributes", (parts with { AfterAttributes = [[0x05, 0x00]] }).Encode()),
			("version 1", (parts with { Version = [0x02, 0x01, 0x01] }).Encode()),
			("negative version", (parts with { Version = [0x02, 0x01, 0xFF] }).Encode()),
			("redundant version byte", (parts with { Version = [0x02, 0x02, 0x00, 0x00] }).Encode()),
			("explicitly tagged version", (parts with { Version = Tlv(0xA0, [0x02, 0x01, 0x00]) }).Encode()),
			("no version", (parts with { Version = [] }).Encode()),
			("subject not a Name", (parts with { Subject = [0x02, 0x01, 0x01] }).Encode()),
			("empty relative name", (parts with { Subject = Sequence(Tlv(0x31)) }).Encode()),
			("no subject public key info", (parts with { SubjectPublicKeyInfo = [] }).Encode()),
			("public key info not a SEQUENCE", (parts with { SubjectPublicKeyInfo = [0x05, 0x00] }).Encode()),
			("public key with unused bits", (parts with { SubjectPublicKeyInfo = Sequence(Sequence(Oid("1.2.3")), [0x03, 0x02, 0x01, 0x00]) }).Encode()),
			("signature algorithm not a SEQUENCE", (parts with { SignatureAlgorithm = [0x05, 0x00] }).Encode()),
			("signature with unused bits", (parts with { Signature = [0x03, 0x03, 0x01, 0x02, 0x00] }).Encode()),
			("signature not a BIT STRING", (parts with { Signature = [0x04, 0x02, 0x00, 0x01] }).Encode()),
			("no attributes", (parts with { Attributes = [] }).Encode()),
			("attributes with tag [1]", (parts with { Attributes = Tlv(0xA1) }).Encode()),
			("attributes primitive", (parts with { Attributes = Tlv(0x80) }).Encode()),
			("attributes not implicitly tagged", (parts with { Attributes = Tlv(0x31) }).Encode()),
			("attributes out of order", (parts with { Attributes = Tlv(0xA0, larger, smaller) }).Encode()),
			("attribute not a SEQUENCE", (parts with { Attributes = AttributeSet([0x05, 0x00]) }).Encode()),
			("attribute type not an OID", (parts with { Attributes = AttributeSet(Sequence([0x05, 0x00], Tlv(0x31, [0x05, 0x00]))) }).Encode()),
			("attribute without a SET", (parts with { Attributes = AttributeSet(Sequence(Oid("1.2.3"))) }).Encode()),
			("attribute with no values", (parts with { Attributes = AttributeSet(Attribute("1.2.3")) }).Encode()),
			("attribute values not a SET", (parts with { Attributes = AttributeSet(Sequence(Oid("1.2.3"), Sequence([0x05, 0x00]))) }).Encode()),
			("attribute field after the values", (parts with { Attributes = AttributeSet(Sequence(Oid("1.2.3"), Tlv(0x31, [0x05, 0x00]), [0x05, 0x00])) }).Encode()),
			("attribute value truncated", (parts with { Attributes = AttributeSet(Sequence(Oid("1.2.3"), Tlv(0x31, [0x02, 0x05, 0x01]))) }).Encode()),
			("extensionRequest with no values", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid)) }).Encode()),
			("extensionRequest with two values", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, extensions, otherExtensions)) }).Encode()),
			("two extensionRequest attributes", (parts with { Attributes = Tlv(0xA0, Attribute(ExtensionRequestOid, extensions), Attribute(ExtensionRequestOid, extensions)) }).Encode()),
			("extensionRequest without extensions", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, Sequence())) }).Encode()),
			("extensionRequest not a SEQUENCE", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, [0x05, 0x00])) }).Encode()),
			("malformed extension", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, Sequence(Sequence([0x05, 0x00])))) }).Encode()),
			("critical encoded as FALSE", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, Sequence(Extension(BasicConstraintsOid, [0x30, 0x00], [0x01, 0x01, 0x00])))) }).Encode()),
			("repeated extension", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, Sequence(Extension(BasicConstraintsOid, [0x30, 0x00]), Extension(BasicConstraintsOid, [0x30, 0x03, 0x01, 0x01, 0xFF])))) }).Encode()),
			("empty key usage", (parts with { Attributes = AttributeSet(Attribute(ExtensionRequestOid, Sequence(Extension(KeyUsageOid, [0x03, 0x01, 0x00])))) }).Encode()),
		];

		foreach ((string reason, byte[] malformed) in cases)
		{
			yield return () => (reason, malformed);
		}
	}

	[Test]
	[MethodDataSource(nameof(MalformedRequests))]
	public async Task RejectsMalformedRequests(string reason, byte[] encoded)
	{
		await Assert.That(() => CertificationRequest.Decode(encoded)).Throws<ArgumentException>().WithParameterName("source").Because(reason);
	}

	// RFC 7468, Sec. 7: the label is CERTIFICATE REQUEST; other labels and the text around the block are ignored.
	[Test]
	public async Task DecodesThePemBlockOfTheRequest()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificationRequest request = new CertificationRequestBuilder(Name("CN=PEM")).Create(key, SignatureAlgorithm.EcdsaSha256);
		string block = PemEncoding.WriteString("CERTIFICATE REQUEST", request.Encoded.Span);
		string certificateBlock = PemEncoding.WriteString("CERTIFICATE", SelfSignedP256().Encoded.Span);
		string otherRequest = PemEncoding.WriteString("NEW CERTIFICATE REQUEST", new CertificationRequestBuilder(Name("CN=Other")).Create(key, SignatureAlgorithm.EcdsaSha256).Encoded.Span);
		string invalid = PemEncoding.WriteString("CERTIFICATE REQUEST", (byte[])[0x30, 0x00]);

		CertificationRequest decoded = CertificationRequest.DecodePem($"text\n{otherRequest}\n{certificateBlock}\n{block}\n{invalid}\ntext");

		using (Assert.Multiple())
		{
			await Assert.That(decoded.Encoded).IsEquivalentTo(request.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => CertificationRequest.DecodePem(certificateBlock + otherRequest)).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => CertificationRequest.DecodePem(certificateBlock + otherRequest)).Throws<ArgumentException>().WithMessageContaining("The text holds no CERTIFICATE REQUEST block.");
			await Assert.That(() => CertificationRequest.DecodePem(invalid)).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	[Test]
	public async Task HoldsACopyOfTheEncoding()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] encoded = new CertificationRequestBuilder(Name("CN=Copy")).Create(key, SignatureAlgorithm.EcdsaSha256).Encoded.ToArray();
		CertificationRequest decoded = CertificationRequest.Decode(encoded);
		Array.Clear(encoded);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.VerifySignature(key)).IsTrue();
			await Assert.That(new X500DistinguishedName(decoded.Subject.Span).Name).IsEqualTo("CN=Copy");
		}
	}

	// A request names its one signature algorithm, so one that does not fit the key or the signature only fails verification.
	[Test]
	public async Task VerifySignatureReturnsFalseForAlgorithmsThatDoNotMatch()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		using EcdsaP256 other = EcdsaP256.GenerateKey();
		using Ed25519 ed25519 = Ed25519.GenerateKey();
		RequestParts parts = new() { SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key) };
		byte[] signature = Sign(key, SignatureAlgorithm.EcdsaSha256, parts.Info());
		byte[] signed = (parts with { Signature = BitString(signature) }).Encode();

		CertificationRequest valid = CertificationRequest.Decode(signed);
		CertificationRequest wrongHash = CertificationRequest.Decode((parts with { SignatureAlgorithm = AlgorithmIdentifier.FromSignatureAlgorithm(SignatureAlgorithm.EcdsaSha384).Encoded.ToArray(), Signature = BitString(signature) }).Encode());
		CertificationRequest unknown = CertificationRequest.Decode((parts with { SignatureAlgorithm = Sequence(Oid("1.2.3.4")), Signature = BitString(signature) }).Encode());
		CertificationRequest wrongParameters = CertificationRequest.Decode((parts with { SignatureAlgorithm = Sequence(Oid("1.2.840.10045.4.3.2"), [0x05, 0x00]), Signature = BitString(signature) }).Encode());

		using (Assert.Multiple())
		{
			await Assert.That(valid.VerifySignature(key)).IsTrue();
			await Assert.That(valid.VerifySignature(other)).IsFalse();
			await Assert.That(valid.VerifySignature(ed25519)).IsFalse();
			await Assert.That(wrongHash.VerifySignature(key)).IsFalse();
			await Assert.That(unknown.VerifySignature(key)).IsFalse();
			await Assert.That(wrongParameters.VerifySignature(key)).IsFalse();
			await Assert.That(() => valid.VerifySignature(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	[Test]
	public async Task VerifySignatureThrowsForADisposedKey()
	{
		EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificationRequest request = new CertificationRequestBuilder(Name("CN=Disposed")).Create(key, SignatureAlgorithm.EcdsaSha256);
		key.Dispose();

		await Assert.That(() => request.VerifySignature(key)).ThrowsExactly<ObjectDisposedException>();
	}

	// Without extensions the attributes are an empty [0], so no extensionRequest attribute is written; RFC 2986 requires the field itself.
	[Test]
	public async Task WritesAnEmptyAttributesFieldWithoutExtensions()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificationRequest request = new CertificationRequestBuilder(Name("CN=Plain")).Create(key, SignatureAlgorithm.EcdsaSha256);
		byte[] expected = Sequence([0x02, 0x01, 0x00], Name("CN=Plain"), ExportSubjectPublicKeyInfo(key), Tlv(0xA0));

		using (Assert.Multiple())
		{
			await Assert.That(request.CertificationRequestInfo).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(request.RequestedExtensions).IsEmpty();
		}
	}

	[Test]
	public async Task WritesTheExtensionRequestAttribute()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificationRequestBuilder builder = new(Name("CN=Extensions"));
		builder.Extensions.Add(new CertificateExtension(BasicConstraintsOid, true, [0x30, 0x00]));
		byte[] attributes = Tlv(0xA0, Attribute(ExtensionRequestOid, Sequence(Extension(BasicConstraintsOid, [0x30, 0x00], [0x01, 0x01, 0xFF]))));
		byte[] expected = Sequence([0x02, 0x01, 0x00], Name("CN=Extensions"), ExportSubjectPublicKeyInfo(key), attributes);

		await Assert.That(builder.Create(key, SignatureAlgorithm.EcdsaSha256).CertificationRequestInfo).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task SubjectNamesMustBeNames()
	{
		byte[] name = Name("CN=Copy");
		CertificationRequestBuilder builder = new(name);
		name[^1] ^= 1;

		using (Assert.Multiple())
		{
			await Assert.That(new X500DistinguishedName(builder.SubjectName.Span).Name).IsEqualTo("CN=Copy");
			await Assert.That(new CertificationRequestBuilder(Sequence()).SubjectName).IsEquivalentTo(Sequence(), CollectionOrdering.Matching);

			foreach (byte[] invalid in (byte[][])[[], [0x02, 0x01, 0x01], [.. Name("CN=Trailing"), 0x00], Sequence(Tlv(0x31))])
			{
				await Assert.That(() => new CertificationRequestBuilder(invalid)).Throws<ArgumentException>().WithParameterName("subjectName").Because(Convert.ToHexString(invalid));
			}
		}
	}

	[Test]
	public async Task InvalidRequestsThrow()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		using EcdsaP256 publicOnly = EcdsaP256.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key));
		CertificationRequestBuilder builder = new(Name("CN=Invalid"));
		CertificationRequestBuilder duplicate = new(Name("CN=Duplicate"));
		duplicate.Extensions.Add(new CertificateExtension(BasicConstraintsOid, false, [0x30, 0x00]));
		duplicate.Extensions.Add(new CertificateExtension(BasicConstraintsOid, false, [0x30, 0x00]));
		CertificationRequestBuilder withNull = new(Name("CN=Null"));
		withNull.Extensions.Add(null!);
		CertificationRequestBuilder notDer = new(Name("CN=Key usage"));
		notDer.Extensions.Add(new CertificateExtension(KeyUsageOid, true, [0x03, 0x02, 0x00, 0x80]));

		using (Assert.Multiple())
		{
			await Assert.That(() => builder.Create(null!, SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => builder.Create(key, SignatureAlgorithm.MLDsa44)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(() => builder.Create(key, (SignatureAlgorithm)0x7FFF)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(() => builder.Create(publicOnly, SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => duplicate.Create(key, SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => withNull.Create(key, SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => notDer.Create(key, SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<InvalidOperationException>();
		}
	}

	public static IEnumerable<Func<SignatureAlgorithm>> RsaAlgorithmCases()
	{
		foreach (SignatureAlgorithm algorithm in RsaAlgorithms)
		{
			yield return () => algorithm;
		}
	}

	// The extensions and the other attributes of a request that the platform writes, which CryptoBase decodes and verifies.
	private static async Task AssertDecodesBclRequest(CertificateRequest request, SignatureAlgorithm algorithm)
	{
		byte[] subjectAlternativeName = SubjectAlternativeName("bcl.example").RawData;
		byte[] password = Tlv(0x0C, "secret"u8.ToArray());
		request.CertificateExtensions.Add(new X509Extension(SubjectAlternativeNameOid, subjectAlternativeName, false));
		request.CertificateExtensions.Add(new X509Extension(BasicConstraintsOid, [0x30, 0x00], true));
		request.OtherRequestAttributes.Add(new AsnEncodedData(ChallengePasswordOid, password));

		byte[] encoded = request.CreateSigningRequest();
		CertificationRequest decoded = CertificationRequest.Decode(encoded);
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(decoded.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm signatureAlgorithm)).IsTrue();
			await Assert.That(signatureAlgorithm).IsEqualTo(algorithm);
			await Assert.That(decoded.VerifySignature(publicKey)).IsTrue();
			await Assert.That(CertificationRequest.Decode(FlipSignature(decoded)).VerifySignature(publicKey)).IsFalse();
			await Assert.That(decoded.Subject).IsEquivalentTo(request.SubjectName.RawData, CollectionOrdering.Matching);
			await Assert.That(decoded.RequestedExtensions.Select(static extension => (extension.Oid, extension.Critical, Convert.ToHexString(extension.Value.Span)))).IsEquivalentTo([(SubjectAlternativeNameOid, false, Convert.ToHexString(subjectAlternativeName)), (BasicConstraintsOid, true, "3000")], CollectionOrdering.Matching);
			await Assert.That(decoded.Encoded.Span.IndexOf(password) >= 0).IsTrue();
		}
	}

	// The platform verifies RSA, ECDSA and, where it has it, ML-DSA.
	private static bool BclVerifies(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.Ed25519 or SignatureAlgorithm.Ed448 or SignatureAlgorithm.SM2SM3 => false,
			SignatureAlgorithm.MLDsa44 or SignatureAlgorithm.MLDsa65 or SignatureAlgorithm.MLDsa87 => BclMLDsa.IsSupported,
			_ => true
		};
	}

	private static byte[] FlipSignature(CertificationRequest request)
	{
		byte[] encoded = request.Encoded.ToArray();
		encoded[^1] ^= 1;
		return encoded;
	}

	private static byte[] BitString(byte[] value)
	{
		return Tlv(0x03, [0x00], value);
	}

	private static byte[] Attribute(string oid, params byte[][] values)
	{
		return Sequence(Oid(oid), SetOf(null, values));
	}

	// The [0] SET OF attributes, in the order that DER requires.
	private static byte[] AttributeSet(params byte[][] attributes)
	{
		return SetOf(AttributesTag, attributes);
	}

	private static byte[] SetOf(Asn1Tag? tag, byte[][] elements)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSetOf(tag))
		{
			foreach (byte[] element in elements)
			{
				writer.WriteEncodedValue(element);
			}
		}

		return writer.Encode();
	}

	// The fields of a request, each a DER TLV, which the tests replace to make the encodings to check.
	private sealed record RequestParts
	{
		public byte[] Version { get; init; } = [0x02, 0x01, 0x00];

		public byte[] Subject { get; init; } = Name("CN=Request");

		public byte[] SubjectPublicKeyInfo { get; init; } = DefaultSubjectPublicKeyInfo;

		public byte[] Attributes { get; init; } = Tlv(0xA0);

		public byte[][] AfterAttributes { get; init; } = [];

		public byte[] SignatureAlgorithm { get; init; } = Sequence(Oid("1.2.840.10045.4.3.2"));

		public byte[] Signature { get; init; } = [0x03, 0x03, 0x00, 0x01, 0x02];

		private static byte[] DefaultSubjectPublicKeyInfo { get; } = CreateSubjectPublicKeyInfo();

		public byte[] Info()
		{
			return Sequence([Version, Subject, SubjectPublicKeyInfo, Attributes, .. AfterAttributes]);
		}

		public byte[] Encode()
		{
			return Sequence(Info(), SignatureAlgorithm, Signature);
		}

		private static byte[] CreateSubjectPublicKeyInfo()
		{
			using EcdsaP256 key = EcdsaP256.GenerateKey();
			return ExportSubjectPublicKeyInfo(key);
		}
	}

	// Signs with a CryptoBase key for an algorithm that the platform does not have.
	private sealed class KeySignatureGenerator(ISignatureKey key, SignatureAlgorithm algorithm) : X509SignatureGenerator
	{
		public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
		{
			return AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray();
		}

		public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
		{
			return Sign(key, algorithm, data);
		}

		protected override PublicKey BuildPublicKey()
		{
			return PublicKey.CreateFromSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key), out _);
		}
	}
}
