using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.X509;

internal static class X509TestUtils
{
	public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
	public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

	public static readonly DateTimeOffset Now = X509Time.TruncateToSeconds(DateTimeOffset.UtcNow);

	public static byte[] Name(string distinguishedName)
	{
		return new X500DistinguishedName(distinguishedName).RawData;
	}

	// The contents of a DER TLV with a one-byte tag.
	public static byte[] Contents(byte[] tlv)
	{
		int lengthOfLength = tlv[1] < 0x80 ? 0 : tlv[1] & 0x7F;
		return tlv.AsSpan(2 + lengthOfLength).ToArray();
	}

	// The TLV with its length in one byte more than DER allows.
	public static byte[] WithRedundantLengthByte(byte[] tlv)
	{
		int lengthOfLength = tlv[1] < 0x80 ? 0 : tlv[1] & 0x7F;
		byte[] length = lengthOfLength is 0 ? [tlv[1]] : tlv.AsSpan(2, lengthOfLength).ToArray();
		return [tlv[0], (byte)(0x80 | length.Length + 1), 0x00, .. length, .. Contents(tlv)];
	}

	// Trust in root alone, without revocation checks or certificate downloads.
	public static X509ChainPolicy TrustOnly(X509Certificate2 root)
	{
		X509ChainPolicy policy = new() { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true };
		policy.CustomTrustStore.Add(root);
		return policy;
	}

	// Whether the platform builds a chain for a certificate that it trusts as its own root, and the chain status otherwise.
	public static (bool Built, string Status) BuildTrustingItself(X509Certificate2 certificate)
	{
		using X509Chain chain = new();
		chain.ChainPolicy = TrustOnly(certificate);
		bool built = chain.Build(certificate);
		return (built, string.Join(", ", chain.ChainStatus.Select(static status => status.Status)));
	}

	public static byte[] Time(DateTimeOffset value, bool generalized = false)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		if (generalized)
		{
			writer.WriteGeneralizedTime(value, omitFractionalSeconds: true);
		}
		else
		{
			writer.WriteUtcTime(value, 2049);
		}

		return writer.Encode();
	}

	public static byte[] Extension(string oid, byte[] value, byte[]? critical = null)
	{
		return Sequence(Oid(oid), critical ?? [], Tlv(0x04, value));
	}

	public static byte[] Extensions(params byte[][] extensions)
	{
		return Tlv(0xA3, Sequence(extensions));
	}

	public static Certificate SelfSigned(ISignatureKey key, SignatureAlgorithm algorithm, string subject = "CN=Test", params CertificateExtension[] extensions)
	{
		CertificateBuilder builder = new(Name(subject));

		foreach (CertificateExtension extension in extensions)
		{
			builder.Extensions.Add(extension);
		}

		return builder.CreateSelfSigned(key, algorithm, Now.AddDays(-1), Now.AddDays(30));
	}

	public static Certificate SelfSignedP256()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		return SelfSigned(key, SignatureAlgorithm.EcdsaSha256);
	}

	public static X509Certificate2 BclSelfSigned(ECDsa key, HashAlgorithmName hash, string subject = "CN=Test", Action<CertificateRequest>? configure = null)
	{
		CertificateRequest request = new(subject, key, hash);
		configure?.Invoke(request);
		return request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
	}

	public static X509Extension SubjectAlternativeName(params string[] dnsNames)
	{
		SubjectAlternativeNameBuilder builder = new();

		foreach (string name in dnsNames)
		{
			if (System.Net.IPAddress.TryParse(name, out System.Net.IPAddress? address))
			{
				builder.AddIpAddress(address);
			}
			else
			{
				builder.AddDnsName(name);
			}
		}

		return builder.Build();
	}

	public static X509EnhancedKeyUsageExtension EnhancedKeyUsage(string oid)
	{
		return new X509EnhancedKeyUsageExtension([new Oid(oid)], false);
	}

	// The fields of a certificate, each a DER TLV, which the tests replace to make the encodings to check.
	public sealed record CertificateParts
	{
		public byte[]? Version { get; init; } = Tlv(0xA0, [0x02, 0x01, 0x02]);

		public byte[] SerialNumber { get; init; } = [0x02, 0x01, 0x01];

		public byte[] InnerSignature { get; init; } = EcdsaSha256;

		public byte[] Issuer { get; init; } = Name("CN=Issuer");

		public byte[] Validity { get; init; } = Sequence(Time(Now), Time(Now.AddDays(1)));

		public byte[] Subject { get; init; } = Name("CN=Subject");

		public byte[] SubjectPublicKeyInfo { get; init; } = DefaultSubjectPublicKeyInfo;

		public byte[][] AfterSubjectPublicKeyInfo { get; init; } = [];

		public byte[] OuterSignature { get; init; } = EcdsaSha256;

		public byte[] SignatureValue { get; init; } = [0x03, 0x03, 0x00, 0x01, 0x02];

		public byte[][] AfterSignature { get; init; } = [];

		public static byte[] EcdsaSha256 => Sequence(Oid("1.2.840.10045.4.3.2"));

		public static byte[] EcdsaSha384 => Sequence(Oid("1.2.840.10045.4.3.3"));

		private static byte[] DefaultSubjectPublicKeyInfo { get; } = CreateSubjectPublicKeyInfo();

		public byte[] TbsCertificate()
		{
			return Sequence([.. Version is null ? [] : (byte[][])[Version], SerialNumber, InnerSignature, Issuer, Validity, Subject, SubjectPublicKeyInfo, .. AfterSubjectPublicKeyInfo]);
		}

		public byte[] Encode()
		{
			return Sequence([TbsCertificate(), OuterSignature, SignatureValue, .. AfterSignature]);
		}

		private static byte[] CreateSubjectPublicKeyInfo()
		{
			using EcdsaP256 key = EcdsaP256.GenerateKey();
			return ExportSubjectPublicKeyInfo(key);
		}
	}
}
