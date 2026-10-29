using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
internal class CertificateBuilderTest
{
	public static IEnumerable<Func<(KeyType Type, SignatureAlgorithm Algorithm)>> SigningCases()
	{
		foreach (KeyType type in KeyTypes)
		{
			foreach (SignatureAlgorithm algorithm in type.Algorithms)
			{
				yield return () => (type, algorithm);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(SigningCases))]
	public async Task SelfSignedCertificatesHoldTheKey(KeyType type, SignatureAlgorithm algorithm)
	{
		using ISignatureKey key = type.GenerateKey();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] name = Name("CN=Self-signed, O=CryptoBase");
		DateTimeOffset notBefore = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
		DateTimeOffset notAfter = notBefore.AddYears(1);

		Certificate certificate = new CertificateBuilder(name).CreateSelfSigned(key, algorithm, notBefore, notAfter);
		Certificate decoded = Certificate.Decode(certificate.Encoded.Span);
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(decoded.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.Version).IsEqualTo(3);
			await Assert.That(decoded.Issuer.ToArray()).IsEquivalentTo(name, CollectionOrdering.Matching);
			await Assert.That(decoded.Subject.ToArray()).IsEquivalentTo(name, CollectionOrdering.Matching);
			await Assert.That(decoded.NotBefore).IsEqualTo(notBefore);
			await Assert.That(decoded.NotAfter).IsEqualTo(notAfter);
			await Assert.That(decoded.PublicKeyInfo.Encoded.ToArray()).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(decoded.SignatureAlgorithm.Encoded.ToArray()).IsEquivalentTo(AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(decoded.Extensions).IsEmpty();
			await Assert.That(decoded.SerialNumber.Length).IsEqualTo(16);
			await Assert.That(decoded.SerialNumber.Span[0]).IsBetween((byte)0x40, (byte)0x7F);
			await Assert.That(publicKey.GetType()).IsEqualTo(type.Type);
			await Assert.That(decoded.VerifySignature(key)).IsTrue();
			await Assert.That(decoded.VerifySignature(publicKey)).IsTrue();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task TheBclAcceptsEcdsaCertificates([Matrix(256, 384, 521)] int curveBits, [Matrix(SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.EcdsaSha384, SignatureAlgorithm.EcdsaSha512)] SignatureAlgorithm algorithm)
	{
		using ISignatureKey key = EcdsaCurve(curveBits).Type.GenerateKey();
		CertificateBuilder builder = new(Name("CN=interop.example"));
		builder.Extensions.Add(new CertificateExtension("2.5.29.19", true, new X509BasicConstraintsExtension(true, false, 0, true).RawData));
		builder.Extensions.Add(new CertificateExtension("2.5.29.17", false, SubjectAlternativeName("interop.example").RawData));

		Certificate certificate = builder.CreateSelfSigned(key, algorithm, Now.AddDays(-1), Now.AddDays(1));
		using X509Certificate2 loaded = X509CertificateLoader.LoadCertificate(certificate.Encoded.Span);
		using ECDsa? publicKey = loaded.GetECDsaPublicKey();
		(bool built, string status) = BuildTrustingItself(loaded);

		using (Assert.Multiple())
		{
			await Assert.That(loaded.Version).IsEqualTo(3);
			await Assert.That(loaded.SubjectName.Name).IsEqualTo("CN=interop.example");
			await Assert.That(loaded.SignatureAlgorithm.Value).IsEqualTo(certificate.SignatureAlgorithm.Oid);
			await Assert.That(publicKey is not null && publicKey.VerifyData(certificate.TbsCertificate.Span, certificate.Signature.Span, EcdsaTestUtils.HashName(algorithm), DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
			await Assert.That(loaded.MatchesHostname("interop.example")).IsTrue();
			await Assert.That(built).IsTrue().Because(status);
		}
	}

	[Test]
	public async Task ExtensionsAndSerialNumberAreKept()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificateBuilder builder = new(Name("CN=Extensions"))
		{
			SerialNumber = (byte[])[0x00, 0x80, 0x01]
		};
		builder.Extensions.Add(new CertificateExtension("1.3.6.1.4.1.99999.1", true, [0x05, 0x00]));
		builder.Extensions.Add(new CertificateExtension("2.5.29.15", false, [0x03, 0x02, 0x07, 0x80]));

		Certificate certificate = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now);

		using (Assert.Multiple())
		{
			await Assert.That(certificate.SerialNumber.ToArray()).IsEquivalentTo((byte[])[0x00, 0x80, 0x01], CollectionOrdering.Matching);
			await Assert.That(certificate.Extensions.Select(static extension => (extension.Oid, extension.Critical, Convert.ToHexString(extension.Value.Span)))).IsEquivalentTo([("1.3.6.1.4.1.99999.1", true, "0500"), ("2.5.29.15", false, "03020780")], CollectionOrdering.Matching);
			await Assert.That(certificate.NotBefore).IsEqualTo(certificate.NotAfter);
		}
	}

	[Test]
	public async Task RandomSerialNumbersDiffer()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificateBuilder builder = new(Name("CN=Serial"));
		Certificate first = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now);
		Certificate second = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now);

		await Assert.That(first.SerialNumber.ToArray()).IsNotEquivalentTo(second.SerialNumber.ToArray());
	}

	[Test]
	public async Task TimesAreUtcSecondsInTheTypeOfTheirYear()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificateBuilder builder = new(Name("CN=Times"));
		DateTimeOffset lastUtcTime = new(2049, 12, 31, 23, 59, 59, TimeSpan.Zero);
		DateTimeOffset local = new DateTimeOffset(2049, 12, 31, 23, 59, 59, TimeSpan.FromHours(8)).AddTicks(TimeSpan.TicksPerSecond - 1);

		Certificate utcTimes = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, new DateTimeOffset(1950, 1, 1, 0, 0, 0, TimeSpan.Zero), lastUtcTime);
		Certificate generalizedTimes = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, new DateTimeOffset(1949, 12, 31, 23, 59, 59, TimeSpan.Zero), lastUtcTime.AddSeconds(1));
		Certificate truncated = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, local, local);

		using (Assert.Multiple())
		{
			await Assert.That(ValidityTags(utcTimes)).IsEquivalentTo((byte[])[0x17, 0x17], CollectionOrdering.Matching);
			await Assert.That(ValidityTags(generalizedTimes)).IsEquivalentTo((byte[])[0x18, 0x18], CollectionOrdering.Matching);
			await Assert.That(utcTimes.NotAfter).IsEqualTo(lastUtcTime);
			await Assert.That(generalizedTimes.NotAfter).IsEqualTo(lastUtcTime.AddSeconds(1));
			await Assert.That(truncated.NotBefore).IsEqualTo(new DateTimeOffset(2049, 12, 31, 15, 59, 59, TimeSpan.Zero));
			await Assert.That(truncated.NotBefore.Offset).IsEqualTo(TimeSpan.Zero);
		}
	}

	[Test]
	public async Task InvalidRequestsThrow()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		using EcdsaP256 publicOnly = PublicOnly(key);
		using ISignatureKey mlDsa = KeyTypes[0].GenerateKey();
		CertificateBuilder builder = new(Name("CN=Invalid"));
		CertificateBuilder duplicate = new(Name("CN=Duplicate"));
		duplicate.Extensions.Add(new CertificateExtension("2.5.29.19", false, [0x30, 0x00]));
		duplicate.Extensions.Add(new CertificateExtension("2.5.29.19", false, [0x30, 0x00]));
		CertificateBuilder withNull = new(Name("CN=Null"));
		withNull.Extensions.Add(null!);
		CertificateBuilder emptyKeyUsage = new(Name("CN=Key usage"));
		emptyKeyUsage.Extensions.Add(new CertificateExtension("2.5.29.15", true, [0x03, 0x01, 0x00]));

		using (Assert.Multiple())
		{
			await Assert.That(() => builder.CreateSelfSigned(null!, SignatureAlgorithm.EcdsaSha256, Now, Now)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => builder.CreateSelfSigned(key, SignatureAlgorithm.MLDsa44, Now, Now)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(() => builder.CreateSelfSigned(mlDsa, SignatureAlgorithm.EcdsaSha256, Now, Now)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(() => builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now.AddSeconds(-1))).Throws<ArgumentException>().WithParameterName("notAfter");
			await Assert.That(() => builder.CreateSelfSigned(publicOnly, SignatureAlgorithm.EcdsaSha256, Now, Now)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => duplicate.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => withNull.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => emptyKeyUsage.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now)).ThrowsExactly<InvalidOperationException>();
		}
	}

	[Test]
	public async Task SubjectNamesMustBeNonemptyNames()
	{
		using (Assert.Multiple())
		{
			foreach (byte[] name in (byte[][])[[], [0x30, 0x00], [0x02, 0x01, 0x01], [.. Name("CN=Trailing"), 0x00], Sequence(Tlv(0x31))])
			{
				await Assert.That(() => new CertificateBuilder(name)).Throws<ArgumentException>().WithParameterName("subjectName").Because(Convert.ToHexString(name));
			}
		}
	}

	[Test]
	public async Task SerialNumbersArePositiveIntegersOfAtMost159Bits()
	{
		CertificateBuilder builder = new(Name("CN=Serial"));

		using (Assert.Multiple())
		{
			foreach (byte[] valid in (byte[][])[[0x01], [0x80], [0xFF], [0x00, 0x7F], [0x00, 0x80], [0x00, 0x00, 0x80], [0x7F, .. new byte[19]], [0x00, 0x7F, .. new byte[19]], []])
			{
				builder.SerialNumber = valid;
				await Assert.That(builder.SerialNumber.ToArray()).IsEquivalentTo(valid, CollectionOrdering.Matching);
			}

			foreach (byte[] invalid in (byte[][])[[0x00], [0x00, 0x00], [0x80, .. new byte[19]], [0x01, .. new byte[20]]])
			{
				await Assert.That(() => builder.SerialNumber = invalid).Throws<ArgumentException>().WithParameterName("value").Because(Convert.ToHexString(invalid));
			}
		}
	}

	// The INTEGER holds the unsigned serial number without leading zero bytes and with the zero byte that its sign needs, as the platform reads it.
	[Test]
	[Arguments("01", "01")]
	[Arguments("8001", "008001")]
	[Arguments("000001", "01")]
	[Arguments("008001", "008001")]
	[Arguments("00008001", "008001")]
	[Arguments("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
	public async Task SerialNumbersAreWrittenAsPositiveIntegers(string serialNumber, string expected)
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		CertificateBuilder builder = new(Name("CN=Serial")) { SerialNumber = Convert.FromHexString(serialNumber) };

		Certificate certificate = builder.CreateSelfSigned(key, SignatureAlgorithm.EcdsaSha256, Now, Now);
		using X509Certificate2 loaded = X509CertificateLoader.LoadCertificate(certificate.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(certificate.SerialNumber.Span)).IsEqualTo(expected);
			await Assert.That(Convert.ToHexString(loaded.SerialNumberBytes.Span)).IsEqualTo(expected);
		}
	}

	[Test]
	public async Task ExtensionsCheckTheirIdentifier()
	{
		byte[] value = [0x30, 0x00];
		CertificateExtension extension = new("2.5.29.19", true, value);
		value[0] = 0;

		using (Assert.Multiple())
		{
			await Assert.That(extension.Value.ToArray()).IsEquivalentTo((byte[])[0x30, 0x00], CollectionOrdering.Matching);
			await Assert.That(() => new CertificateExtension(null!, false, [])).ThrowsExactly<ArgumentNullException>();

			foreach (string oid in (string[])["", "2", "2.5.", "x.1", "3.1"])
			{
				await Assert.That(() => new CertificateExtension(oid, false, [])).Throws<ArgumentException>().WithParameterName("oid").Because(oid);
			}
		}
	}

	private static EcdsaP256 PublicOnly(EcdsaP256 key)
	{
		return EcdsaP256.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key));
	}

	// The tags of notBefore and notAfter, in the Validity right after the issuer.
	private static byte[] ValidityTags(Certificate certificate)
	{
		ReadOnlySpan<byte> tbs = certificate.TbsCertificate.Span;
		int validity = tbs.IndexOf(certificate.Issuer.Span) + certificate.Issuer.Length;
		int notAfter = validity + 2 + 2 + tbs[validity + 3];
		return [tbs[validity + 2], tbs[notAfter]];
	}
}
