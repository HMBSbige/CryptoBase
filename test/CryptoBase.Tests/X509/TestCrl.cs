using CryptoBase.Abstractions.Signatures;
using CryptoBase.X509;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

internal static class TestCrl
{
	public const string AuthorityKeyIdentifierOid = "2.5.29.35";
	public const string IssuerAlternativeNameOid = "2.5.29.18";
	public const string CrlNumberOid = "2.5.29.20";
	public const string DeltaCrlIndicatorOid = "2.5.29.27";
	public const string IssuingDistributionPointOid = "2.5.29.28";
	public const string ReasonCodeOid = "2.5.29.21";
	public const string InvalidityDateOid = "2.5.29.24";
	public const string CrlDistributionPointsOid = "2.5.29.31";
	public const string PrivateOid = "1.3.6.1.4.1.55738.666.1";

	public static readonly byte[] Critical = [0x01, 0x01, 0xFF];

	public static readonly byte[] NullValue = [0x05, 0x00];

	// The fields of a CRL, each a DER TLV; a null field is left out.
	public sealed record Template
	{
		public byte[]? Version { get; init; } = [0x02, 0x01, 0x01];

		public byte[] InnerSignature { get; init; } = EcdsaSha256;

		public required byte[] Issuer { get; init; }

		public byte[] ThisUpdate { get; init; } = Time(Now.AddHours(-1));

		public byte[]? NextUpdate { get; init; } = Time(Now.AddDays(1));

		// The entries, each the DER of a SEQUENCE; null leaves the list out.
		public byte[][]? Entries { get; init; }

		// The extensions, each the DER of an Extension; null leaves the list out.
		public byte[][]? Extensions { get; init; }

		public byte[] OuterSignature { get; init; } = EcdsaSha256;

		public byte[][] AfterSignature { get; init; } = [];

		public static byte[] EcdsaSha256 => Sequence(Oid("1.2.840.10045.4.3.2"));

		public byte[] TbsCertList()
		{
			return Sequence([
				.. Version is null ? [] : (byte[][])[Version],
				InnerSignature,
				Issuer,
				ThisUpdate,
				.. NextUpdate is null ? [] : (byte[][])[NextUpdate],
				.. Entries is null ? [] : (byte[][])[Sequence(Entries)],
				.. Extensions is null ? [] : (byte[][])[Tlv(0xA0, Sequence(Extensions))]
			]);
		}

		public byte[] Encode(Func<byte[], byte[]> sign)
		{
			byte[] tbs = TbsCertList();
			return Sequence([tbs, OuterSignature, Tlv(0x03, [0x00, .. sign(tbs)]), .. AfterSignature]);
		}

		// The encoding signed by a CA with ECDSA and SHA-256.
		public byte[] Encode(TestPki.Authority authority)
		{
			return Encode(tbs => Signatures.SignatureTestUtils.Sign(authority.Key, SignatureAlgorithm.EcdsaSha256, tbs));
		}

		public CertificateRevocationList Decode(TestPki.Authority authority)
		{
			return CertificateRevocationList.Decode(Encode(authority));
		}
	}

	// The template of a conforming CRL by a CA: with an authority key identifier, a CRL number and the extra extensions.
	public static Template Conforming(TestPki.Authority authority, byte[][]? entries = null, params byte[][] extensions)
	{
		return new Template
		{
			Issuer = authority.Name,
			Entries = entries,
			Extensions = [AuthorityKeyIdentifier(authority.KeyIdentifier), CrlNumber(1), .. extensions]
		};
	}

	public static byte[] Entry(byte[] serialNumber, DateTimeOffset? date = null, params byte[][] extensions)
	{
		byte[] time = Time(date ?? Now.AddHours(-2));
		return extensions.Length is 0 ? Sequence(Tlv(0x02, serialNumber), time) : Sequence(Tlv(0x02, serialNumber), time, Sequence(extensions));
	}

	public static byte[] AuthorityKeyIdentifier(byte[] keyIdentifier, byte[]? critical = null)
	{
		return Extension(AuthorityKeyIdentifierOid, Sequence(Tlv(0x80, keyIdentifier)), critical);
	}

	public static byte[] CrlNumber(byte number, byte[]? critical = null)
	{
		return Extension(CrlNumberOid, [0x02, 0x01, number], critical);
	}

	public static byte[] ReasonCode(byte reason, byte[]? critical = null)
	{
		return Extension(ReasonCodeOid, [0x0A, 0x01, reason], critical);
	}

	public static byte[] IssuingDistributionPoint(params byte[][] fields)
	{
		return Extension(IssuingDistributionPointOid, Sequence(fields), Critical);
	}

	// A DistributionPointName with fullName entries: [0] { [0] GeneralNames } under the tag that the field has.
	public static byte[] FullName(byte outerTag, params byte[][] names)
	{
		return Tlv(outerTag, Tlv(0xA0, names));
	}

	// A DistributionPointName with a nameRelativeToCRLIssuer of one attribute.
	public static byte[] RelativeName(byte outerTag, byte[] attribute)
	{
		return Tlv(outerTag, Tlv(0xA1, attribute));
	}

	// One CommonName attribute, as X500DistinguishedName encodes it: SEQUENCE { OID, PrintableString }.
	public static byte[] CommonName(string value)
	{
		return Sequence(Oid("2.5.4.3"), Tlv(0x13, System.Text.Encoding.ASCII.GetBytes(value)));
	}

	public static CertificateExtension DistributionPoints(params byte[][] points)
	{
		return new CertificateExtension(CrlDistributionPointsOid, false, Sequence(points));
	}

	// The key of a CA as a SignatureKey over the key that it issues with.
	public static RevocationResult Check(CertificateRevocationList crl, Certificate certificate, TestPki.Authority authority, DateTimeOffset? time = null)
	{
		return RevocationChecker.CheckCrl(crl, certificate, authority.Certificate, authority.Key, time ?? Now);
	}

	public static byte[] SerialNumberOf(Certificate certificate)
	{
		return certificate.SerialNumber.ToArray();
	}
}
