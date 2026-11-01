using CryptoBase.Abstractions.Signatures;
using CryptoBase.Tests.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class AlgorithmIdentifierTest
{
	private static readonly (SignatureAlgorithm Algorithm, string Oid)[] Mapped =
	[
		(SignatureAlgorithm.EcdsaSha256, "1.2.840.10045.4.3.2"),
		(SignatureAlgorithm.EcdsaSha384, "1.2.840.10045.4.3.3"),
		(SignatureAlgorithm.EcdsaSha512, "1.2.840.10045.4.3.4"),
		(SignatureAlgorithm.MLDsa44, "2.16.840.1.101.3.4.3.17"),
		(SignatureAlgorithm.MLDsa65, "2.16.840.1.101.3.4.3.18"),
		(SignatureAlgorithm.MLDsa87, "2.16.840.1.101.3.4.3.19"),
	];

	// sha256WithRSAEncryption, sha384WithRSAEncryption and sha512WithRSAEncryption (RFC 4055, Sec. 5).
	private static readonly (SignatureAlgorithm Algorithm, string Oid)[] RsaPkcs1 =
	[
		(SignatureAlgorithm.RsaPkcs1Sha256, "1.2.840.113549.1.1.11"),
		(SignatureAlgorithm.RsaPkcs1Sha384, "1.2.840.113549.1.1.12"),
		(SignatureAlgorithm.RsaPkcs1Sha512, "1.2.840.113549.1.1.13"),
	];

	private static readonly (SignatureAlgorithm Algorithm, string Hash, int SaltLength)[] RsaPss =
	[
		(SignatureAlgorithm.RsaPssSha256, Sha256Oid, 32),
		(SignatureAlgorithm.RsaPssSha384, Sha384Oid, 48),
		(SignatureAlgorithm.RsaPssSha512, Sha512Oid, 64),
	];

	[Test]
	public async Task MappedAlgorithmsRoundTripWithoutParameters()
	{
		using (Assert.Multiple())
		{
			foreach ((SignatureAlgorithm algorithm, string oid) in Mapped)
			{
				AlgorithmIdentifier identifier = AlgorithmIdentifier.FromSignatureAlgorithm(algorithm);

				await Assert.That(identifier.Oid).IsEqualTo(oid);
				await Assert.That(identifier.Parameters.IsEmpty).IsTrue();
				await Assert.That(identifier.Encoded.ToArray()).IsEquivalentTo(Sequence(Oid(oid)), CollectionOrdering.Matching);
				await Assert.That(identifier.TryGetSignatureAlgorithm(out SignatureAlgorithm mapped)).IsTrue();
				await Assert.That(mapped).IsEqualTo(algorithm);
			}
		}
	}

	// RFC 4055, Sec. 5: "the parameters MUST be NULL. Implementations MUST accept the parameters being absent as well as present."
	[Test]
	public async Task RsaPkcs1IdentifiersHaveNullParametersAndMatchWithoutThem()
	{
		using (Assert.Multiple())
		{
			foreach ((SignatureAlgorithm algorithm, string oid) in RsaPkcs1)
			{
				AlgorithmIdentifier identifier = AlgorithmIdentifier.FromSignatureAlgorithm(algorithm);

				await Assert.That(identifier.Oid).IsEqualTo(oid);
				await Assert.That(identifier.Parameters.ToArray()).IsEquivalentTo((byte[])[0x05, 0x00], CollectionOrdering.Matching);
				await Assert.That(identifier.Encoded.ToArray()).IsEquivalentTo(Sequence(Oid(oid), [0x05, 0x00]), CollectionOrdering.Matching);
				await Assert.That(MappedAlgorithm(identifier.Encoded.ToArray())).IsEqualTo(algorithm);
				await Assert.That(MappedAlgorithm(Sequence(Oid(oid)))).IsEqualTo(algorithm);
			}
		}
	}

	// Hash AlgorithmIdentifiers with NULL parameters, as RFC 4055, Sec. 2.1, defines sha256Identifier and the others.
	[Test]
	public async Task RsaPssIdentifiersAreThoseOfOpenSsl()
	{
		(SignatureAlgorithm Algorithm, string Certificate)[] openSsl =
		[
			(SignatureAlgorithm.RsaPssSha256, OpenSslCertificates.RsaPssSha256),
			(SignatureAlgorithm.RsaPssSha384, OpenSslCertificates.RsassaPssKeyWithoutParametersSha384),
			(SignatureAlgorithm.RsaPssSha512, OpenSslCertificates.RsassaPssKeySha512),
			(SignatureAlgorithm.RsaPkcs1Sha384, OpenSslCertificates.RsaPkcs1Sha384),
		];

		using (Assert.Multiple())
		{
			foreach ((SignatureAlgorithm algorithm, string certificate) in openSsl)
			{
				AlgorithmIdentifier identifier = AlgorithmIdentifier.FromSignatureAlgorithm(algorithm);
				await Assert.That(identifier.Encoded.ToArray()).IsEquivalentTo(Certificate.DecodePem(certificate).SignatureAlgorithm.Encoded.ToArray(), CollectionOrdering.Matching).Because(algorithm.ToString());
			}

			foreach ((SignatureAlgorithm algorithm, string hash, int saltLength) in RsaPss)
			{
				AlgorithmIdentifier identifier = AlgorithmIdentifier.FromSignatureAlgorithm(algorithm);
				byte[] expected = RsassaPssIdentifier(hash: hash, maskHash: hash, saltLength: saltLength);

				await Assert.That(identifier.Oid).IsEqualTo("1.2.840.113549.1.1.10");
				await Assert.That(identifier.Encoded.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(identifier.Parameters.ToArray()).IsEquivalentTo(expected.AsSpan(2 + 11).ToArray(), CollectionOrdering.Matching);
				await Assert.That(identifier.TryGetSignatureAlgorithm(out SignatureAlgorithm mapped)).IsTrue();
				await Assert.That(mapped).IsEqualTo(algorithm);
			}
		}
	}

	// Hash AlgorithmIdentifiers without parameters, which RFC 4055, Sec. 2.1, requires accepting.
	[Test]
	public async Task RsaIdentifiersOfTheBclMatch()
	{
		using RSA key = CreateRsa();

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in RsaAlgorithms)
			{
				using X509Certificate2 certificate = BclSelfSigned(key, algorithm);
				await Assert.That(Certificate.Decode(certificate.RawData).SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm mapped) ? mapped : default).IsEqualTo(algorithm);
			}
		}
	}

	// RFC 4055: each hash AlgorithmIdentifier with NULL or absent parameters (Sec. 2.1), and the trailer field absent or present (Sec. 3.1).
	[Test]
	public async Task RsaPssIdentifiersMatchInEachEncodingThatRfc4055Allows()
	{
		using (Assert.Multiple())
		{
			foreach ((SignatureAlgorithm algorithm, string hash, int saltLength) in RsaPss)
			{
				foreach (bool nullParameters in (bool[])[false, true])
				{
					foreach (bool maskNullParameters in (bool[])[false, true])
					{
						foreach (int? trailerField in (int?[])[null, 1])
						{
							byte[] encoded = RsassaPssIdentifier(hash: hash, maskHash: hash, saltLength: saltLength, trailerField: trailerField, nullParameters: nullParameters, maskNullParameters: maskNullParameters);
							await Assert.That(MappedAlgorithm(encoded)).IsEqualTo(algorithm).Because(Convert.ToHexString(encoded));
						}
					}
				}
			}
		}
	}

	[Test]
	public async Task OtherRsaIdentifiersDoNotMatch()
	{
		byte[] sha256Null = Sequence(Oid(Sha256Oid), [0x05, 0x00]);
		byte[] mgf1Sha256 = Tlv(0xA1, Sequence(Oid(Mgf1Oid), sha256Null));
		byte[] salt32 = Tlv(0xA2, [0x02, 0x01, 0x20]);
		(string Case, byte[] Encoded)[] cases =
		[
			("sha1WithRSAEncryption", Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00])),
			("sha256WithRSAEncryption with other parameters", Sequence(Oid("1.2.840.113549.1.1.11"), [0x04, 0x00])),
			("id-RSASSA-PSS without parameters", RsassaPssIdentifier(withParameters: false)),
			("default saltLength of 20", RsassaPssIdentifier(saltLength: null)),
			("saltLength 20", RsassaPssIdentifier(saltLength: 20)),
			("saltLength 0", RsassaPssIdentifier(saltLength: 0)),
			("saltLength 33", RsassaPssIdentifier(saltLength: 33)),
			("SHA-384 saltLength with SHA-256", RsassaPssIdentifier(saltLength: 48)),
			("default hash, SHA-1", RsassaPssIdentifier(hash: null, saltLength: 20)),
			("default mask generation function", RsassaPssIdentifier(maskHash: null)),
			("MGF1 with another hash", RsassaPssIdentifier(maskHash: Sha384Oid)),
			("SHA-1", RsassaPssIdentifier(hash: "1.3.14.3.2.26", maskHash: "1.3.14.3.2.26", saltLength: 20)),
			("SHA-224", RsassaPssIdentifier(hash: "2.16.840.1.101.3.4.2.4", maskHash: "2.16.840.1.101.3.4.2.4", saltLength: 28)),
			("another mask generation function", RsassaPssIdentifier(maskGenerationFunction: "1.2.840.113549.1.1.99")),
			("trailer field 2", RsassaPssIdentifier(trailerField: 2)),
			("hash parameters other than NULL", Sequence(Oid("1.2.840.113549.1.1.10"), Sequence(Tlv(0xA0, Sequence(Oid(Sha256Oid), [0x04, 0x00])), mgf1Sha256, salt32))),
			("MGF1 without a hash", Sequence(Oid("1.2.840.113549.1.1.10"), Sequence(Tlv(0xA0, sha256Null), Tlv(0xA1, Sequence(Oid(Mgf1Oid))), salt32))),
			("fields out of order", Sequence(Oid("1.2.840.113549.1.1.10"), Sequence(mgf1Sha256, Tlv(0xA0, sha256Null), salt32))),
			("field after the trailer field", Sequence(Oid("1.2.840.113549.1.1.10"), Sequence(Tlv(0xA0, sha256Null), mgf1Sha256, salt32, Tlv(0xA3, [0x02, 0x01, 0x01]), Tlv(0xA4, [0x05, 0x00])))),
			("implicit tags", Sequence(Oid("1.2.840.113549.1.1.10"), Sequence(Tlv(0xA0, Oid(Sha256Oid), [0x05, 0x00]), mgf1Sha256, Tlv(0x82, [0x20])))),
			("long-form length in the parameters", Sequence(Oid("1.2.840.113549.1.1.10"), Sequence(WithRedundantLengthByte(Tlv(0xA0, sha256Null)), mgf1Sha256, salt32))),
			("NULL parameters", Sequence(Oid("1.2.840.113549.1.1.10"), [0x05, 0x00])),
		];

		using (Assert.Multiple())
		{
			foreach ((string @case, byte[] encoded) in cases)
			{
				await Assert.That(MappedAlgorithm(encoded)).IsEqualTo((SignatureAlgorithm)0).Because(@case);
			}
		}
	}

	[Test]
	public async Task EcdsaIdentifiersMatchTheBcl()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in EcdsaTestUtils.Algorithms)
			{
				using X509Certificate2 certificate = BclSelfSigned(key, EcdsaTestUtils.HashName(algorithm));
				await Assert.That(Certificate.Decode(certificate.RawData).SignatureAlgorithm.Encoded.ToArray()).IsEquivalentTo(AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray(), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task OtherAlgorithmsAreNotSupported()
	{
		IEnumerable<SignatureAlgorithm> mapped = [.. Mapped.Select(static mapped => mapped.Algorithm), .. RsaAlgorithms];

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[.. Enum.GetValues<SignatureAlgorithm>().Except(mapped), 0, (SignatureAlgorithm)int.MaxValue])
			{
				await Assert.That(() => AlgorithmIdentifier.FromSignatureAlgorithm(algorithm)).ThrowsExactly<NotSupportedException>().Because(algorithm.ToString());
			}
		}
	}

	[Test]
	public async Task OnlyTheRequiredEncodingMaps()
	{
		CertificateParts parts = new();
		byte[] withNull = Sequence(Oid("1.2.840.10045.4.3.2"), [0x05, 0x00]);
		byte[] rsa = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]);
		AlgorithmIdentifier nullParameters = Certificate.Decode((parts with { InnerSignature = withNull, OuterSignature = withNull }).Encode()).SignatureAlgorithm;
		AlgorithmIdentifier other = Certificate.Decode((parts with { InnerSignature = rsa, OuterSignature = rsa }).Encode()).SignatureAlgorithm;

		using (Assert.Multiple())
		{
			await Assert.That(nullParameters.Oid).IsEqualTo("1.2.840.10045.4.3.2");
			await Assert.That(nullParameters.Parameters.ToArray()).IsEquivalentTo((byte[])[0x05, 0x00], CollectionOrdering.Matching);
			await Assert.That(nullParameters.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm)).IsFalse();
			await Assert.That(algorithm).IsEqualTo((SignatureAlgorithm)0);
			await Assert.That(other.TryGetSignatureAlgorithm(out _)).IsFalse();
		}
	}

	// The algorithm that an encoded AlgorithmIdentifier names, as the signature algorithm of a certificate, or 0.
	private static SignatureAlgorithm MappedAlgorithm(byte[] encoded)
	{
		AlgorithmIdentifier identifier = Certificate.Decode((new CertificateParts() with { InnerSignature = encoded, OuterSignature = encoded }).Encode()).SignatureAlgorithm;
		return identifier.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm) ? algorithm : 0;
	}
}
