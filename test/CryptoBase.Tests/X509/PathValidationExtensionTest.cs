using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// The basic constraints and extended key usage extensions (RFC 5280, Sec. 4.2.1.9 and 4.2.1.12), which certification path validation reads.
public class PathValidationExtensionTest
{
	private const string BasicConstraintsOid = "2.5.29.19";
	private const string ExtendedKeyUsageOid = "2.5.29.37";

	[Test]
	[Arguments(false, false, 0)]
	[Arguments(true, false, 0)]
	[Arguments(true, true, 0)]
	[Arguments(true, true, 7)]
	[Arguments(true, true, int.MaxValue)]
	public async Task BasicConstraintsDecodeAsTheBclEncodes(bool certificateAuthority, bool hasPathLengthConstraint, int pathLengthConstraint)
	{
		X509BasicConstraintsExtension expected = new(certificateAuthority, hasPathLengthConstraint, pathLengthConstraint, true);

		BasicConstraints? decoded = WithExtensions(Extension(BasicConstraintsOid, expected.RawData, [0x01, 0x01, 0xFF])).GetBasicConstraints();

		using (Assert.Multiple())
		{
			await Assert.That(decoded?.CertificateAuthority).IsEqualTo(expected.CertificateAuthority);
			await Assert.That(decoded?.PathLengthConstraint).IsEqualTo(expected.HasPathLengthConstraint ? expected.PathLengthConstraint : null);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] Value, bool? CertificateAuthority, int? PathLengthConstraint)>> BasicConstraintsCases()
	{
		// A path length constraint without cA, which CAs must not issue, is left to the validator.
		yield return () => ("path length without cA", Sequence([0x02, 0x01, 0x03]), false, 3);
		yield return () => ("path length of 2^31", Sequence(Tlv(0x01, [0xFF]), [0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00]), true, int.MaxValue);
		yield return () => ("path length of 2^64", Sequence(Tlv(0x01, [0xFF]), [0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]), true, int.MaxValue);
		yield return () => ("cA encoded as FALSE", Sequence([0x01, 0x01, 0x00]), null, null);
		yield return () => ("cA as a BER TRUE", Sequence([0x01, 0x01, 0x01]), null, null);
		yield return () => ("negative path length", Sequence(Tlv(0x01, [0xFF]), [0x02, 0x01, 0xFF]), null, null);
		yield return () => ("path length with a redundant leading byte", Sequence(Tlv(0x01, [0xFF]), [0x02, 0x02, 0x00, 0x01]), null, null);
		yield return () => ("fields out of order", Sequence([0x02, 0x01, 0x01], Tlv(0x01, [0xFF])), null, null);
		yield return () => ("field after the path length", Sequence([0x02, 0x01, 0x01], [0x05, 0x00]), null, null);
		yield return () => ("trailing byte", [.. Sequence(), 0x00], null, null);
		yield return () => ("not a SEQUENCE", [0x05, 0x00], null, null);
	}

	[Test]
	[MethodDataSource(nameof(BasicConstraintsCases))]
	public async Task BasicConstraintsDecodeOnlyFromDer(string @case, byte[] value, bool? certificateAuthority, int? pathLengthConstraint)
	{
		Certificate certificate = WithExtensions(Extension(BasicConstraintsOid, value));

		if (certificateAuthority is null)
		{
			await Assert.That(() => certificate.GetBasicConstraints()).ThrowsExactly<CryptographicException>().Because(@case);
			return;
		}

		BasicConstraints? decoded = certificate.GetBasicConstraints();

		using (Assert.Multiple())
		{
			await Assert.That(decoded?.CertificateAuthority).IsEqualTo(certificateAuthority).Because(@case);
			await Assert.That(decoded?.PathLengthConstraint).IsEqualTo(pathLengthConstraint).Because(@case);
		}
	}

	[Test]
	public async Task ExtendedKeyUsageDecodesAsTheBclEncodes()
	{
		X509EnhancedKeyUsageExtension expected = new([new Oid(ServerAuthenticationOid), new Oid(ClientAuthenticationOid), new Oid("1.3.6.1.4.1.99999.1"), new Oid(ExtendedKeyUsage.AnyExtendedKeyUsage)], false);

		ExtendedKeyUsage? decoded = WithExtensions(Extension(ExtendedKeyUsageOid, expected.RawData)).GetExtendedKeyUsage();

		using (Assert.Multiple())
		{
			await Assert.That(decoded?.Purposes).IsEquivalentTo(expected.EnhancedKeyUsages.Cast<Oid>().Select(static oid => oid.Value ?? ""), CollectionOrdering.Matching);
			await Assert.That(decoded?.Contains(ClientAuthenticationOid)).IsTrue();
			await Assert.That(decoded?.Contains("1.3.6.1.5.5.7.3.3")).IsFalse();
		}
	}

	public static IEnumerable<Func<(string Case, byte[] Value)>> MalformedExtendedKeyUsages()
	{
		yield return () => ("no purposes", Sequence());
		yield return () => ("a purpose that is not an OBJECT IDENTIFIER", Sequence(Oid(ServerAuthenticationOid), [0x05, 0x00]));
		yield return () => ("trailing byte", [.. Sequence(Oid(ServerAuthenticationOid)), 0x00]);
		yield return () => ("SET instead of SEQUENCE", Tlv(0x31, Oid(ServerAuthenticationOid)));
	}

	[Test]
	[MethodDataSource(nameof(MalformedExtendedKeyUsages))]
	public async Task MalformedExtendedKeyUsagesThrow(string @case, byte[] value)
	{
		await Assert.That(() => WithExtensions(Extension(ExtendedKeyUsageOid, value)).GetExtendedKeyUsage()).ThrowsExactly<CryptographicException>().Because(@case);
	}

	// RFC 5280 does not forbid a purpose twice.
	[Test]
	public async Task ExtendedKeyUsageKeepsRepeatedPurposes()
	{
		ExtendedKeyUsage? decoded = WithExtensions(Extension(ExtendedKeyUsageOid, Sequence(Oid(ServerAuthenticationOid), Oid(ServerAuthenticationOid)))).GetExtendedKeyUsage();

		await Assert.That(decoded?.Purposes).IsEquivalentTo([ServerAuthenticationOid, ServerAuthenticationOid], CollectionOrdering.Matching);
	}
}
