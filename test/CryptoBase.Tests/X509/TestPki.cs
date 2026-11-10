using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// Certificates for the tests of path validation, which a CryptoBase key signs, with the fields and extensions that a test chooses.
internal static class TestPki
{
	public const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
	public const string NameConstraintsOid = "2.5.29.30";
	public const string CertificatePoliciesOid = "2.5.29.32";
	public const string PolicyMappingsOid = "2.5.29.33";
	public const string PolicyConstraintsOid = "2.5.29.36";
	public const string InhibitAnyPolicyOid = "2.5.29.54";
	public const string AnyPolicyOid = "2.5.29.32.0";

	// The fields of a certificate; the subject and issuer are DER Names, and Extensions are written as they are.
	public sealed record Template
	{
		public int Version { get; init; } = 3;

		public byte[] SerialNumber { get; init; } = [0x01];

		public required byte[] Subject { get; init; }

		public required byte[] SubjectPublicKeyInfo { get; init; }

		public DateTimeOffset NotBefore { get; init; } = Now.AddDays(-1);

		public DateTimeOffset NotAfter { get; init; } = Now.AddDays(30);

		public CertificateExtension[] Extensions { get; init; } = [];
	}

	// A CA: its name, key and certificate, and the signature algorithm with which it issues. The instance owns the key.
	public sealed class Authority(byte[] name, ISignatureKey key, Certificate certificate, SignatureAlgorithm algorithm = SignatureAlgorithm.EcdsaSha256) : IDisposable
	{
		public byte[] Name { get; } = name;

		public ISignatureKey Key { get; } = key;

		public Certificate Certificate { get; } = certificate;

		public SignatureAlgorithm Algorithm { get; } = algorithm;

		public byte[] KeyIdentifier => KeyIdentifierOf(Certificate.PublicKeyInfo.Encoded.Span);

		// A self-signed root with a new P-256 key, by default with the extensions of a CA.
		public static Authority CreateRoot(string name = "CN=Root", CertificateExtension[]? extensions = null, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, CertificateExtension[]? more = null)
		{
			EcdsaP256 key = EcdsaP256.GenerateKey();
			byte[] subject = X509TestUtils.Name(name);
			byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
			Template template = new()
			{
				Subject = subject,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				NotBefore = notBefore ?? Now.AddDays(-1),
				NotAfter = notAfter ?? Now.AddDays(30),
				Extensions = [.. extensions ?? CaExtensions(subjectPublicKeyInfo), .. more ?? []]
			};

			return new Authority(subject, key, Sign(template, subject, key, SignatureAlgorithm.EcdsaSha256));
		}

		// A CA with a new P-256 key that this one issues, by default with the extensions of a CA and an authority key identifier.
		public Authority CreateIntermediate(string name = "CN=Intermediate", CertificateExtension[]? extensions = null, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, byte[]? subject = null, CertificateExtension[]? more = null)
		{
			EcdsaP256 key = EcdsaP256.GenerateKey();
			byte[] subjectName = subject ?? X509TestUtils.Name(name);
			byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
			Certificate certificate = Issue(new Template
			{
				Subject = subjectName,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				NotBefore = notBefore ?? Now.AddDays(-1),
				NotAfter = notAfter ?? Now.AddDays(30),
				Extensions = [.. extensions ?? [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(KeyIdentifier)], .. more ?? []]
			});

			return new Authority(subjectName, key, certificate);
		}

		// A leaf for a new P-256 key, by default with the DNS name example.com.
		public Certificate IssueLeaf(string name = "CN=Leaf", CertificateExtension[]? extensions = null, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, CertificateExtension[]? more = null)
		{
			using EcdsaP256 key = EcdsaP256.GenerateKey();
			return Issue(new Template
			{
				Subject = X509TestUtils.Name(name),
				SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key),
				NotBefore = notBefore ?? Now.AddDays(-1),
				NotAfter = notAfter ?? Now.AddDays(30),
				Extensions = [.. extensions ?? [SubjectAlternativeNames("example.com"), AuthorityKeyIdentifier(KeyIdentifier)], .. more ?? []]
			});
		}

		public Certificate Issue(Template template)
		{
			return Sign(template, Name, Key, Algorithm);
		}

		public void Dispose()
		{
			Key.Dispose();
		}
	}

	// The extensions of a CA: basic constraints with cA, a key usage of keyCertSign and cRLSign, both critical, and a subject key identifier.
	public static CertificateExtension[] CaExtensions(ReadOnlySpan<byte> subjectPublicKeyInfo, int? pathLength = null)
	{
		return [BasicConstraints(true, pathLength), KeyUsage(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign), SubjectKeyIdentifier(KeyIdentifierOf(subjectPublicKeyInfo))];
	}

	public static byte[] KeyIdentifierOf(ReadOnlySpan<byte> subjectPublicKeyInfo)
	{
		return SHA256.HashData(subjectPublicKeyInfo).AsSpan(0, 20).ToArray();
	}

	public static Certificate Sign(Template template, byte[] issuer, ISignatureKey key, SignatureAlgorithm algorithm)
	{
		return Sign(template, issuer, AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray(), tbs => Signatures.SignatureTestUtils.Sign(key, algorithm, tbs));
	}

	// The certificate whose TBSCertificate, with the signature algorithm given, sign signs.
	public static Certificate Sign(Template template, byte[] issuer, byte[] signatureAlgorithm, Func<byte[], byte[]> sign)
	{
		byte[] tbs = TbsCertificate(template, issuer, signatureAlgorithm);
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(tbs);
			writer.WriteEncodedValue(signatureAlgorithm);
			writer.WriteBitString(sign(tbs));
		}

		return Certificate.Decode(writer.Encode());
	}

	public static byte[] TbsCertificate(Template template, byte[] issuer, byte[] signatureAlgorithm)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			if (template.Version > 1)
			{
				using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
				{
					writer.WriteInteger(template.Version - 1);
				}
			}

			writer.WriteIntegerUnsigned(template.SerialNumber);
			writer.WriteEncodedValue(signatureAlgorithm);
			writer.WriteEncodedValue(issuer);

			using (writer.PushSequence())
			{
				WriteTime(writer, template.NotBefore);
				WriteTime(writer, template.NotAfter);
			}

			writer.WriteEncodedValue(template.Subject);
			writer.WriteEncodedValue(template.SubjectPublicKeyInfo);

			if (template.Extensions.Length > 0)
			{
				using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true)))
				using (writer.PushSequence())
				{
					foreach (CertificateExtension extension in template.Extensions)
					{
						using (writer.PushSequence())
						{
							writer.WriteObjectIdentifier(extension.Oid);

							if (extension.Critical)
							{
								writer.WriteBoolean(true);
							}

							writer.WriteOctetString(extension.Value.Span);
						}
					}
				}
			}
		}

		return writer.Encode();
	}

	// RFC 5280, Sec. 4.1.2.5: UTCTime for the years 1950 through 2049 and GeneralizedTime for the others.
	private static void WriteTime(AsnWriter writer, DateTimeOffset value)
	{
		if (value.Year is >= 1950 and <= 2049)
		{
			writer.WriteUtcTime(value, 2049);
		}
		else
		{
			writer.WriteGeneralizedTime(value, omitFractionalSeconds: true);
		}
	}

	public static CertificateExtension BasicConstraints(bool certificateAuthority, int? pathLength = null, bool critical = true)
	{
		return Of(new X509BasicConstraintsExtension(certificateAuthority, pathLength is not null, pathLength ?? 0, critical));
	}

	public static CertificateExtension KeyUsage(X509KeyUsageFlags flags, bool critical = true)
	{
		return Of(new X509KeyUsageExtension(flags, critical));
	}

	public static CertificateExtension ExtendedKeyUsage(params string[] purposes)
	{
		OidCollection oids = [];

		foreach (string purpose in purposes)
		{
			oids.Add(new Oid(purpose));
		}

		return Of(new X509EnhancedKeyUsageExtension(oids, false));
	}

	// DNS names and IP addresses.
	public static CertificateExtension SubjectAlternativeNames(params string[] names)
	{
		return Of(X509TestUtils.SubjectAlternativeName(names));
	}

	// A subject alternative name extension of the GeneralNames given as DER.
	public static CertificateExtension SubjectAlternativeNames(bool critical, params byte[][] names)
	{
		return new CertificateExtension("2.5.29.17", critical, GeneralNames(names));
	}

	public static CertificateExtension SubjectKeyIdentifier(byte[] keyIdentifier, bool critical = false)
	{
		return new CertificateExtension("2.5.29.14", critical, Tlv(0x04, keyIdentifier));
	}

	public static CertificateExtension AuthorityKeyIdentifier(byte[] keyIdentifier, bool critical = false)
	{
		return new CertificateExtension("2.5.29.35", critical, Sequence(Tlv(0x80, keyIdentifier)));
	}

	// NameConstraints with the GeneralNames given as DER for the bases of the permitted and excluded subtrees; null leaves a list out.
	public static CertificateExtension NameConstraints(byte[][]? permitted, byte[][]? excluded = null, bool critical = true)
	{
		byte[] value = Sequence([.. permitted is null ? [] : (byte[][])[Tlv(0xA0, [.. permitted.Select(static name => Sequence(name))])], .. excluded is null ? [] : (byte[][])[Tlv(0xA1, [.. excluded.Select(static name => Sequence(name))])]]);
		return new CertificateExtension(NameConstraintsOid, critical, value);
	}

	public static CertificateExtension CertificatePolicies(params string[] policies)
	{
		return new CertificateExtension(CertificatePoliciesOid, false, Sequence([.. policies.Select(static policy => Sequence(Oid(policy)))]));
	}

	public static CertificateExtension PolicyMappings(params (string Issuer, string Subject)[] mappings)
	{
		return new CertificateExtension(PolicyMappingsOid, false, Sequence([.. mappings.Select(static mapping => Sequence(Oid(mapping.Issuer), Oid(mapping.Subject)))]));
	}

	public static CertificateExtension PolicyConstraints(int? requireExplicitPolicy = null, int? inhibitPolicyMapping = null, bool critical = true)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			if (requireExplicitPolicy is { } require)
			{
				writer.WriteInteger(require, new Asn1Tag(TagClass.ContextSpecific, 0));
			}

			if (inhibitPolicyMapping is { } inhibit)
			{
				writer.WriteInteger(inhibit, new Asn1Tag(TagClass.ContextSpecific, 1));
			}
		}

		return new CertificateExtension(PolicyConstraintsOid, critical, writer.Encode());
	}

	public static CertificateExtension InhibitAnyPolicy(int skipCerts, bool critical = true)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteInteger(skipCerts);
		return new CertificateExtension(InhibitAnyPolicyOid, critical, writer.Encode());
	}

	public static byte[] Rfc822Name(string name)
	{
		return Tlv(0x81, System.Text.Encoding.Latin1.GetBytes(name));
	}

	public static byte[] UniformResourceIdentifier(string uri)
	{
		return Tlv(0x86, System.Text.Encoding.Latin1.GetBytes(uri));
	}

	public static byte[] DirectoryName(string name)
	{
		return DirectoryName(Name(name));
	}

	public static byte[] DirectoryName(byte[] name)
	{
		return Tlv(0xA4, name);
	}

	// An otherName of a private type with a NULL value.
	public static byte[] OtherName()
	{
		return Tlv(0xA0, Oid("1.3.6.1.4.1.55738.666.3"), Tlv(0xA0, [0x05, 0x00]));
	}

	// An iPAddress subtree in CIDR notation, such as 192.0.2.0/24: the address and the mask.
	public static byte[] IPAddressRange(string range)
	{
		string[] parts = range.Split('/');
		byte[] address = IPAddress.Parse(parts[0]).GetAddressBytes();
		int prefix = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
		byte[] mask = new byte[address.Length];

		for (int i = 0; i < prefix; ++i)
		{
			mask[i / 8] |= (byte)(0x80 >> i % 8);
		}

		return Tlv(0x87, [.. address, .. mask]);
	}

	private static CertificateExtension Of(X509Extension extension)
	{
		return new CertificateExtension(extension.Oid?.Value ?? throw new InvalidOperationException(), extension.Critical, extension.RawData);
	}
}
