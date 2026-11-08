using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Tests.Signatures.Rsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.X509TestUtils;
using RsaKey = CryptoBase.Signatures.Rsa.RsaKey;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
internal class CertificateIssuanceTest
{
	private const string SubjectKeyIdentifierOid = "2.5.29.14";
	private const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const X509KeyUsageFlags CaKeyUsage = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;

	private static readonly DateTimeOffset NotBefore = Now.AddDays(-1);
	private static readonly DateTimeOffset NotAfter = Now.AddDays(30);

	// A root of each algorithm issues an intermediate, which issues a leaf, and the path validates.
	[Test]
	[MethodDataSource(typeof(CertificateBuilderTest), nameof(CertificateBuilderTest.SigningCases))]
	public async Task IssuesAChainThatValidates(KeyType type, SignatureAlgorithm algorithm)
	{
		using ISignatureKey rootKey = type.GenerateKey();
		using EcdsaP256 intermediateKey = EcdsaP256.GenerateKey();
		using EcdsaP256 leafKey = EcdsaP256.GenerateKey();
		Certificate root = CreateCa(rootKey, algorithm);
		Certificate intermediate = CreateIntermediate(root, rootKey, algorithm, intermediateKey);
		Certificate leaf = CreateLeaf(intermediate, intermediateKey, leafKey);
		using ISignatureKey rootPublicKey = SignatureKey.ImportSubjectPublicKeyInfo(root.PublicKeyInfo.Encoded.Span);

		CertificateValidationResult result = await Validate([root], [leaf, intermediate], hostName: "example.com");

		using (Assert.Multiple())
		{
			await AssertValid(result, leaf, intermediate, root);
			await Assert.That(intermediate.VerifySignature(rootPublicKey)).IsTrue();
			await Assert.That(leaf.VerifySignature(rootPublicKey)).IsFalse();
		}
	}

	// The platform builds the chain only with its own root in the trust store and its intermediate, so the same certificates fail against another root. macOS verifies no RSASSA-PSS signature in a chain, so that case is skipped there.
	[Test]
	[Arguments(SignatureAlgorithm.EcdsaSha256)]
	[Arguments(SignatureAlgorithm.RsaPkcs1Sha256)]
	[Arguments(SignatureAlgorithm.RsaPssSha256)]
	public async Task TheBclBuildsIssuedChains(SignatureAlgorithm algorithm)
	{
		if (OperatingSystem.IsMacOS() && algorithm is SignatureAlgorithm.RsaPssSha256)
		{
			Skip.Test("macOS does not verify RSASSA-PSS signatures in certificate chains.");
		}

		using ISignatureKey rootKey = algorithm is SignatureAlgorithm.EcdsaSha256 ? EcdsaP256.GenerateKey() : RsaTestUtils.ImportKey();
		using EcdsaP256 intermediateKey = EcdsaP256.GenerateKey();
		using EcdsaP256 leafKey = EcdsaP256.GenerateKey();
		using EcdsaP256 otherKey = EcdsaP256.GenerateKey();
		Certificate root = CreateCa(rootKey, algorithm);
		Certificate intermediate = CreateIntermediate(root, rootKey, algorithm, intermediateKey);
		Certificate leaf = CreateLeaf(intermediate, intermediateKey, leafKey);
		using X509Certificate2 bclRoot = X509CertificateLoader.LoadCertificate(root.Encoded.Span);
		using X509Certificate2 bclIntermediate = X509CertificateLoader.LoadCertificate(intermediate.Encoded.Span);
		using X509Certificate2 bclLeaf = X509CertificateLoader.LoadCertificate(leaf.Encoded.Span);
		using X509Certificate2 bclOther = X509CertificateLoader.LoadCertificate(CreateCa(otherKey, SignatureAlgorithm.EcdsaSha256, "CN=Other").Encoded.Span);
		using X509Chain chain = new();
		chain.ChainPolicy = TrustOnly(bclRoot);
		chain.ChainPolicy.ExtraStore.Add(bclIntermediate);
		using X509Chain otherChain = new();
		otherChain.ChainPolicy = TrustOnly(bclOther);
		otherChain.ChainPolicy.ExtraStore.Add(bclIntermediate);

		bool built = chain.Build(bclLeaf);
		string status = string.Join(", ", chain.ChainStatus.Select(static element => element.Status));
		bool builtWithOtherRoot = otherChain.Build(bclLeaf);

		using (Assert.Multiple())
		{
			await Assert.That(built).IsTrue().Because(status);
			await Assert.That(chain.ChainElements.Count).IsEqualTo(3);
			await Assert.That(builtWithOtherRoot).IsFalse();
		}
	}

	[Test]
	public async Task WritesTheIssuerAndTheCertifiedFields()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);
		CertificateBuilder builder = new(Name("CN=Subject")) { SerialNumber = (byte[])[0x00, 0x80, 0x01] };
		builder.Extensions.Add(new CertificateExtension("1.3.6.1.4.1.99999.1", true, [0x05, 0x00]));

		Certificate certificate = Certificate.Decode(builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter).Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(certificate.Version).IsEqualTo(3);
			await Assert.That(certificate.Issuer.ToArray()).IsEquivalentTo(authority.Certificate.Subject.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.Subject.ToArray()).IsEquivalentTo(Name("CN=Subject"), CollectionOrdering.Matching);
			await Assert.That(certificate.PublicKeyInfo.Encoded.ToArray()).IsEquivalentTo(subjectPublicKeyInfo.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.SerialNumber.ToArray()).IsEquivalentTo((byte[])[0x00, 0x80, 0x01], CollectionOrdering.Matching);
			await Assert.That(certificate.NotBefore).IsEqualTo(NotBefore);
			await Assert.That(certificate.NotAfter).IsEqualTo(NotAfter);
			await Assert.That(certificate.SignatureAlgorithm.Encoded.ToArray()).IsEquivalentTo(AlgorithmIdentifier.FromSignatureAlgorithm(SignatureAlgorithm.EcdsaSha256).Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.VerifySignature(authority.Key)).IsTrue();
			await Assert.That(certificate.VerifySignature(subjectKey)).IsFalse();
			await Assert.That(certificate.Extensions.Select(static extension => extension.Oid)).IsEquivalentTo(["1.3.6.1.4.1.99999.1", AuthorityKeyIdentifierOid, SubjectKeyIdentifierOid], CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task RandomSerialNumbersDiffer()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		CertificateBuilder builder = new(Name("CN=Serial"));
		Certificate first = builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, PublicKeyInfoOf(subjectKey), NotBefore, NotAfter);
		Certificate second = builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, PublicKeyInfoOf(subjectKey), NotBefore, NotAfter);

		using (Assert.Multiple())
		{
			await Assert.That(first.SerialNumber.Length).IsEqualTo(16);
			await Assert.That(first.SerialNumber.ToArray()).IsNotEquivalentTo(second.SerialNumber.ToArray());
		}
	}

	// The key identifier of an issuer with a subject key identifier extension is that value, which TestPki makes differ from the SHA-1 hash; the platform computes the expected extensions.
	[Test]
	public async Task TheAuthorityKeyIdentifierIsTheIssuersSubjectKeyIdentifier()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);

		Certificate certificate = new CertificateBuilder(Name("CN=With SKI")).CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter);

		using (Assert.Multiple())
		{
			await Assert.That(authority.KeyIdentifier).IsNotEquivalentTo(SHA1.HashData(authority.Certificate.PublicKeyInfo.PublicKey.Span));
			await AssertKeyIdentifiers(certificate, authority.KeyIdentifier, subjectPublicKeyInfo);
		}
	}

	// RFC 5280, Sec. 4.2.1.2, method (1), without the issuer's extension.
	[Test]
	public async Task TheAuthorityKeyIdentifierIsTheHashOfAKeyWithoutOne()
	{
		using Authority authority = Authority.CreateRoot(extensions: [BasicConstraints(true), KeyUsage(CaKeyUsage)]);
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);

		Certificate certificate = new CertificateBuilder(Name("CN=Without SKI")).CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter);

		PublicKey issuerPublicKey = PublicKey.CreateFromSubjectPublicKeyInfo(authority.Certificate.PublicKeyInfo.Encoded.Span, out _);
		byte[] expected = new X509SubjectKeyIdentifierExtension(issuerPublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha1, false).SubjectKeyIdentifierBytes.ToArray();

		await AssertKeyIdentifiers(certificate, expected, subjectPublicKeyInfo);
	}

	[Test]
	[Arguments(true, true)]
	[Arguments(true, false)]
	[Arguments(false, true)]
	public async Task KeepsTheKeyIdentifiersOfTheCaller(bool authority, bool subject)
	{
		using Authority issuer = Authority.CreateRoot();
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);
		byte[] authorityKeyIdentifier = [0xA1, 0xA2];
		byte[] subjectKeyIdentifier = [0xB1, 0xB2];
		CertificateBuilder builder = new(Name("CN=Caller"));

		if (subject)
		{
			builder.Extensions.Add(TestPki.SubjectKeyIdentifier(subjectKeyIdentifier, critical: true));
		}

		if (authority)
		{
			builder.Extensions.Add(TestPki.AuthorityKeyIdentifier(authorityKeyIdentifier, critical: true));
		}

		Certificate certificate = builder.CreateSigned(issuer.Certificate, issuer.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter);
		string[] expectedOrder = subject ? [SubjectKeyIdentifierOid, AuthorityKeyIdentifierOid] : [AuthorityKeyIdentifierOid, SubjectKeyIdentifierOid];
		ReadOnlyMemory<byte>? writtenAuthority = certificate.GetAuthorityKeyIdentifier()?.KeyIdentifier;
		ReadOnlyMemory<byte>? writtenSubject = certificate.GetSubjectKeyIdentifier();

		using (Assert.Multiple())
		{
			await Assert.That(certificate.Extensions.Select(static extension => extension.Oid)).IsEquivalentTo(expectedOrder, CollectionOrdering.Matching);
			await Assert.That(writtenAuthority?.ToArray()).IsEquivalentTo(authority ? authorityKeyIdentifier : issuer.KeyIdentifier, CollectionOrdering.Matching);
			await Assert.That(writtenSubject?.ToArray()).IsEquivalentTo(subject ? subjectKeyIdentifier : SHA1.HashData(subjectPublicKeyInfo.PublicKey.Span), CollectionOrdering.Matching);
			await Assert.That(certificate.Extensions.First(static extension => extension.Oid is AuthorityKeyIdentifierOid).Critical).IsEqualTo(authority);
			await Assert.That(certificate.Extensions.First(static extension => extension.Oid is SubjectKeyIdentifierOid).Critical).IsEqualTo(subject);
		}
	}

	// An issuer's malformed subject key identifier matters only to the identifier that would come from it.
	[Test]
	public async Task AMalformedIssuerSubjectKeyIdentifierMattersOnlyWhenUsed()
	{
		using Authority authority = Authority.CreateRoot(extensions: [BasicConstraints(true), KeyUsage(CaKeyUsage), new CertificateExtension(SubjectKeyIdentifierOid, false, [0x05, 0x00])]);
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);
		CertificateBuilder withAuthorityKeyIdentifier = new(Name("CN=Caller"));
		withAuthorityKeyIdentifier.Extensions.Add(TestPki.AuthorityKeyIdentifier([0xA1]));

		using (Assert.Multiple())
		{
			await Assert.That(() => new CertificateBuilder(Name("CN=Auto")).CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("issuer");
			await Assert.That(withAuthorityKeyIdentifier.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter).VerifySignature(authority.Key)).IsTrue();
		}
	}

	public static IEnumerable<Func<(string Reason, Template Template, byte[] IssuerName)>> IssuersThatMayNotSign()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] subject = Name("CN=Not a CA");
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		Template template = new() { Subject = subject, SubjectPublicKeyInfo = subjectPublicKeyInfo };

		(string, Template, byte[])[] cases =
		[
			("version 1", template with { Version = 1 }, subject),
			("no basic constraints", template, subject),
			("cA false", template with { Extensions = [BasicConstraints(false)] }, subject),
			("basic constraints that do not decode", template with { Extensions = [new CertificateExtension("2.5.29.19", true, [0x02, 0x01, 0x01])] }, subject),
			("no keyCertSign", template with { Extensions = [BasicConstraints(true), KeyUsage(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature)] }, subject),
			("empty subject", template with { Subject = Sequence(), Extensions = [BasicConstraints(true), KeyUsage(CaKeyUsage)] }, Name("CN=Above")),
		];

		foreach ((string reason, Template certificate, byte[] issuerName) in cases)
		{
			yield return () => (reason, certificate, issuerName);
		}
	}

	[Test]
	[MethodDataSource(nameof(IssuersThatMayNotSign))]
	public async Task RejectsIssuersThatMayNotSign(string reason, Template template, byte[] issuerName)
	{
		using EcdsaP256 issuerKey = EcdsaP256.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(EcdsaP256.GenerateKey()));
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		Certificate issuer = TestPki.Sign(template with { SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(issuerKey) }, issuerName, issuerKey, SignatureAlgorithm.EcdsaSha256);

		await Assert.That(() => new CertificateBuilder(Name("CN=Subject")).CreateSigned(issuer, issuerKey, SignatureAlgorithm.EcdsaSha256, PublicKeyInfoOf(subjectKey), NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("issuer").Because(reason);
	}

	// A CA may leave out the key usage extension, which then allows any use (RFC 5280, Sec. 4.2.1.3).
	[Test]
	public async Task AcceptsAnIssuerWithoutKeyUsage()
	{
		using Authority authority = Authority.CreateRoot(extensions: [BasicConstraints(true)]);
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();

		Certificate certificate = new CertificateBuilder(Name("CN=Subject")).CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, PublicKeyInfoOf(subjectKey), NotBefore, NotAfter);

		await Assert.That(certificate.VerifySignature(authority.Key)).IsTrue();
	}

	[Test]
	public async Task RejectsKeysThatAreNotTheIssuers()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		using EcdsaP256 otherKey = EcdsaP256.GenerateKey();
		using Ed25519 ed25519 = Ed25519.GenerateKey();
		using RsaKey rsaKey = RsaTestUtils.ImportKey();
		Certificate rsaRoot = CreateCa(rsaKey, SignatureAlgorithm.RsaPkcs1Sha256);
		using RsaKey rsassaPssKey = RsaKey.ImportPkcs8PrivateKey(RsaTestUtils.PrivateKeyInfo(RsassaPssIdentifier(withParameters: false), RsaTestUtils.ExportRsaPrivateKey(rsaKey)));
		CertificateBuilder builder = new(Name("CN=Subject"));
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);

		using (Assert.Multiple())
		{
			await Assert.That(() => builder.CreateSigned(authority.Certificate, otherKey, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("issuerKey");
			await Assert.That(() => builder.CreateSigned(authority.Certificate, ed25519, SignatureAlgorithm.Ed25519, subjectPublicKeyInfo, NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("issuerKey");

			// The same subjectPublicKey under another algorithm identifier.
			await Assert.That(rsassaPssKey.Supports(SignatureAlgorithm.RsaPssSha256)).IsTrue();
			await Assert.That(() => builder.CreateSigned(rsaRoot, rsassaPssKey, SignatureAlgorithm.RsaPssSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("issuerKey");
		}
	}

	// RFC 4055, Sec. 3.1: the parameters of an id-RSASSA-PSS key in the issuer's certificate limit the signatures that verify with it, whatever the object of the private key allows.
	[Test]
	public async Task TheParametersOfTheIssuersKeyLimitTheAlgorithm()
	{
		using RsaKey rsaEncryptionKey = RsaTestUtils.ImportKey();
		byte[] privateKey = RsaTestUtils.ExportRsaPrivateKey(rsaEncryptionKey);
		using RsaKey limitedKey = RsaKey.ImportPkcs8PrivateKey(RsaTestUtils.PrivateKeyInfo(RsassaPssIdentifier(), privateKey));
		using RsaKey unlimitedKey = RsaKey.ImportPkcs8PrivateKey(RsaTestUtils.PrivateKeyInfo(RsassaPssIdentifier(withParameters: false), privateKey));
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		Certificate limited = CreateCa(limitedKey, SignatureAlgorithm.RsaPssSha256);
		Certificate unlimited = CreateCa(unlimitedKey, SignatureAlgorithm.RsaPssSha384, "CN=Unlimited");
		CertificateBuilder builder = new(Name("CN=Subject"));
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);
		using RsaKey limitedPublicKey = RsaKey.ImportSubjectPublicKeyInfo(limited.PublicKeyInfo.Encoded.Span);

		await Assert.That(unlimitedKey.Supports(SignatureAlgorithm.RsaPssSha384)).IsTrue();

		Certificate issued = builder.CreateSigned(limited, unlimitedKey, SignatureAlgorithm.RsaPssSha256, subjectPublicKeyInfo, NotBefore, NotAfter);

		using (Assert.Multiple())
		{
			await Assert.That(() => builder.CreateSigned(limited, unlimitedKey, SignatureAlgorithm.RsaPssSha384, subjectPublicKeyInfo, NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(issued.VerifySignature(limitedPublicKey)).IsTrue();
			await Assert.That(builder.CreateSigned(unlimited, unlimitedKey, SignatureAlgorithm.RsaPssSha384, subjectPublicKeyInfo, NotBefore, NotAfter).SignatureAlgorithm.Oid).IsEqualTo(AlgorithmIdentifier.RsassaPssOid);
		}
	}

	[Test]
	public async Task InvalidRequestsThrow()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 publicOnly = EcdsaP256.ImportSubjectPublicKeyInfo(authority.Certificate.PublicKeyInfo.Encoded.Span);
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);
		CertificateBuilder builder = new(Name("CN=Subject"));
		CertificateBuilder duplicate = new(Name("CN=Duplicate"));
		duplicate.Extensions.Add(new CertificateExtension("2.5.29.19", false, [0x30, 0x00]));
		duplicate.Extensions.Add(new CertificateExtension("2.5.29.19", false, [0x30, 0x00]));
		CertificateBuilder withNull = new(Name("CN=Null"));
		withNull.Extensions.Add(null!);
		CertificateBuilder notDer = new(Name("CN=Key usage"));
		notDer.Extensions.Add(new CertificateExtension("2.5.29.15", true, [0x03, 0x02, 0x00, 0x80]));

		using (Assert.Multiple())
		{
			await Assert.That(() => builder.CreateSigned(null!, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => builder.CreateSigned(authority.Certificate, null!, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, null!, NotBefore, NotAfter)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.MLDsa44, subjectPublicKeyInfo, NotBefore, NotAfter)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(() => builder.CreateSigned(authority.Certificate, publicOnly, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => duplicate.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => withNull.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => notDer.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, NotBefore, NotAfter)).ThrowsExactly<InvalidOperationException>();
		}
	}

	[Test]
	public async Task TheValidityPeriodMustBeWithinTheIssuers()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 subjectKey = EcdsaP256.GenerateKey();
		SubjectPublicKeyInfo subjectPublicKeyInfo = PublicKeyInfoOf(subjectKey);
		CertificateBuilder builder = new(Name("CN=Validity"));
		DateTimeOffset start = authority.Certificate.NotBefore;
		DateTimeOffset end = authority.Certificate.NotAfter;
		TimeSpan halfSecond = TimeSpan.FromMilliseconds(500);

		Certificate exact = builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, start, end);
		Certificate truncated = builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, start.Add(halfSecond), end.Add(halfSecond));

		using (Assert.Multiple())
		{
			await Assert.That(exact.NotBefore).IsEqualTo(start);
			await Assert.That(exact.NotAfter).IsEqualTo(end);
			await Assert.That(truncated.NotBefore).IsEqualTo(start);
			await Assert.That(truncated.NotAfter).IsEqualTo(end);
			await Assert.That(() => builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, start.AddSeconds(-1), end)).Throws<ArgumentException>().WithParameterName("notBefore");
			await Assert.That(() => builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, start.Subtract(halfSecond), end)).Throws<ArgumentException>().WithParameterName("notBefore");
			await Assert.That(() => builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, start, end.AddSeconds(1))).Throws<ArgumentException>().WithParameterName("notAfter");
			await Assert.That(() => builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, subjectPublicKeyInfo, end, start)).Throws<ArgumentException>().WithParameterName("notAfter");
		}
	}

	// The CA verifies the request, copies only the extensions that it accepts, and the certificate validates.
	[Test]
	public async Task IssuesACertificateFromARequest()
	{
		using Authority authority = Authority.CreateRoot();
		using EcdsaP256 requesterKey = EcdsaP256.GenerateKey();
		CertificationRequestBuilder requestBuilder = new(Name("CN=Requester"));
		requestBuilder.Extensions.Add(SubjectAlternativeNames("example.com"));
		requestBuilder.Extensions.Add(BasicConstraints(true));
		CertificationRequest received = CertificationRequest.Decode(requestBuilder.Create(requesterKey, SignatureAlgorithm.EcdsaSha256).Encoded.Span);
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(received.PublicKeyInfo.Encoded.Span);
		CertificateBuilder builder = new(received.Subject.Span);

		foreach (CertificateExtension extension in received.RequestedExtensions)
		{
			if (extension.Oid is "2.5.29.17")
			{
				builder.Extensions.Add(extension);
			}
		}

		Certificate certificate = builder.CreateSigned(authority.Certificate, authority.Key, SignatureAlgorithm.EcdsaSha256, received.PublicKeyInfo, NotBefore, NotAfter);

		using (Assert.Multiple())
		{
			await Assert.That(received.VerifySignature(publicKey)).IsTrue();
			await Assert.That(certificate.GetBasicConstraints()).IsNull();
			await AssertValid(await Validate([authority.Certificate], [certificate], hostName: "example.com"), certificate, authority.Certificate);
		}
	}

	private static async Task AssertKeyIdentifiers(Certificate certificate, byte[] expectedAuthorityKeyIdentifier, SubjectPublicKeyInfo subjectPublicKeyInfo)
	{
		PublicKey publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(subjectPublicKeyInfo.Encoded.Span, out _);
		X509SubjectKeyIdentifierExtension subjectKeyIdentifier = new(publicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha1, false);
		X509AuthorityKeyIdentifierExtension authorityKeyIdentifier = X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(expectedAuthorityKeyIdentifier);
		CertificateExtension writtenAuthority = certificate.Extensions.First(static extension => extension.Oid is AuthorityKeyIdentifierOid);
		CertificateExtension writtenSubject = certificate.Extensions.First(static extension => extension.Oid is SubjectKeyIdentifierOid);

		using (Assert.Multiple())
		{
			await Assert.That(writtenAuthority.Critical).IsFalse();
			await Assert.That(writtenSubject.Critical).IsFalse();
			await Assert.That(writtenAuthority.Value.ToArray()).IsEquivalentTo(authorityKeyIdentifier.RawData, CollectionOrdering.Matching);
			await Assert.That(writtenSubject.Value.ToArray()).IsEquivalentTo(subjectKeyIdentifier.RawData, CollectionOrdering.Matching);
			await Assert.That(certificate.GetAuthorityKeyIdentifier()?.KeyIdentifier?.ToArray()).IsEquivalentTo(expectedAuthorityKeyIdentifier, CollectionOrdering.Matching);
		}
	}

	private static Certificate CreateCa(ISignatureKey key, SignatureAlgorithm algorithm, string name = "CN=Root")
	{
		CertificateBuilder builder = new(Name(name));
		builder.Extensions.Add(BasicConstraints(true));
		builder.Extensions.Add(KeyUsage(CaKeyUsage));
		builder.Extensions.Add(SubjectKeyIdentifierFor(key));
		return builder.CreateSelfSigned(key, algorithm, NotBefore, NotAfter);
	}

	private static Certificate CreateIntermediate(Certificate issuer, ISignatureKey issuerKey, SignatureAlgorithm algorithm, ISignatureKey key)
	{
		CertificateBuilder builder = new(Name("CN=Intermediate"));
		builder.Extensions.Add(BasicConstraints(true));
		builder.Extensions.Add(KeyUsage(CaKeyUsage));
		return builder.CreateSigned(issuer, issuerKey, algorithm, PublicKeyInfoOf(key), NotBefore, NotAfter);
	}

	private static Certificate CreateLeaf(Certificate issuer, ISignatureKey issuerKey, ISignatureKey key)
	{
		CertificateBuilder builder = new(Name("CN=Leaf"));
		builder.Extensions.Add(SubjectAlternativeNames("example.com"));
		return builder.CreateSigned(issuer, issuerKey, SignatureAlgorithm.EcdsaSha256, PublicKeyInfoOf(key), NotBefore, NotAfter);
	}

	private static CertificateExtension SubjectKeyIdentifierFor(ISignatureKey key)
	{
		return TestPki.SubjectKeyIdentifier(KeyIdentifierOf(ExportSubjectPublicKeyInfo(key)));
	}

	private static SubjectPublicKeyInfo PublicKeyInfoOf(ISignatureKey key)
	{
		return SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(key));
	}
}
