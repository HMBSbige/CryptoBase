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
		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[.. Enum.GetValues<SignatureAlgorithm>().Except(Mapped.Select(static mapped => mapped.Algorithm)), 0, (SignatureAlgorithm)int.MaxValue])
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
		byte[] rsa = Sequence(Oid("1.2.840.113549.1.1.11"), [0x05, 0x00]);
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
}
