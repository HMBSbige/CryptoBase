using CryptoBase.Abstractions.Signatures;
using CryptoBase.X509;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

internal static class TestOcsp
{
	public const string BasicOid = "1.3.6.1.5.5.7.48.1.1";
	public const string NonceOid = "1.3.6.1.5.5.7.48.1.2";
	public const string NoCheckOid = "1.3.6.1.5.5.7.48.1.5";
	public const string OcspSigningOid = "1.3.6.1.5.5.7.3.9";

	public static readonly byte[] Good = [0x80, 0x00];

	public static readonly byte[] UnknownStatus = [0x82, 0x00];

	public static readonly byte[] EcdsaSha256 = Sequence(Oid("1.2.840.10045.4.3.2"));

	public static byte[] Revoked(DateTimeOffset time, byte? reason = null)
	{
		return Tlv(0xA1, [.. Time(time, generalized: true), .. reason is { } value ? Tlv(0xA0, [0x0A, 0x01, value]) : []]);
	}

	// The fields of a SingleResponse, each a DER TLV; a null field is left out.
	public sealed record SingleEntry
	{
		public required byte[] CertificateId { get; init; }

		public byte[] Status { get; init; } = Good;

		public byte[] ThisUpdate { get; init; } = Time(Now.AddMinutes(-1), generalized: true);

		public byte[]? NextUpdate { get; init; } = Time(Now.AddHours(1), generalized: true);

		public byte[][]? Extensions { get; init; }

		public byte[] Encode()
		{
			return Sequence([
				CertificateId,
				Status,
				ThisUpdate,
				.. NextUpdate is null ? [] : (byte[][])[Tlv(0xA0, NextUpdate)],
				.. Extensions is null ? [] : (byte[][])[Tlv(0xA1, Sequence(Extensions))]
			]);
		}
	}

	// The fields of a BasicOCSPResponse, signed with key unless Signature is set.
	public sealed record Basic
	{
		public byte[]? Version { get; init; }

		public required byte[] ResponderId { get; init; }

		public byte[] ProducedAt { get; init; } = Time(Now.AddMinutes(-1), generalized: true);

		public required byte[][] Responses { get; init; }

		public byte[][]? Extensions { get; init; }

		public byte[] SignatureAlgorithm { get; init; } = EcdsaSha256;

		public byte[]? Signature { get; init; }

		public byte[][]? Certificates { get; init; }

		public byte[] ResponseData()
		{
			return Sequence([
				.. Version is null ? [] : (byte[][])[Tlv(0xA0, Version)],
				ResponderId,
				ProducedAt,
				Sequence(Responses),
				.. Extensions is null ? [] : (byte[][])[Tlv(0xA1, Sequence(Extensions))]
			]);
		}

		public byte[] Encode(ISignatureKey key, SignatureAlgorithm algorithm = CryptoBase.Abstractions.Signatures.SignatureAlgorithm.EcdsaSha256)
		{
			byte[] tbs = ResponseData();
			byte[] signature = Signature ?? Signatures.SignatureTestUtils.Sign(key, algorithm, tbs);
			byte[] basic = Sequence([tbs, SignatureAlgorithm, Tlv(0x03, [0x00, .. signature]), .. Certificates is null ? [] : (byte[][])[Tlv(0xA0, Sequence(Certificates))]]);
			return Successful(BasicOid, basic);
		}

		public OcspResponse Decode(ISignatureKey key)
		{
			return OcspResponse.Decode(Encode(key));
		}
	}

	public static byte[] Successful(string oid, byte[] response)
	{
		return Sequence([0x0A, 0x01, 0x00], Tlv(0xA0, Sequence(Oid(oid), Tlv(0x04, response))));
	}

	public static byte[] ResponderByName(byte[] name)
	{
		return Tlv(0xA1, name);
	}

	public static byte[] ResponderByKey(byte[] hash)
	{
		return Tlv(0xA2, Tlv(0x04, hash));
	}

	public static byte[] ResponderByKey(Certificate certificate)
	{
		return ResponderByKey(System.Security.Cryptography.SHA1.HashData(certificate.PublicKeyInfo.PublicKey.Span));
	}

	public static byte[] CertificateIdOf(Certificate certificate, Certificate issuer)
	{
		return CertificateIdOf(certificate, certificate.Issuer.ToArray(), issuer.PublicKeyInfo.PublicKey.ToArray());
	}

	// A CertID with SHA-1, over the given name and key.
	public static byte[] CertificateIdOf(Certificate certificate, byte[] issuerName, byte[] issuerKey)
	{
		return Sequence(
			Sequence(Oid("1.3.14.3.2.26"), [0x05, 0x00]),
			Tlv(0x04, System.Security.Cryptography.SHA1.HashData(issuerName)),
			Tlv(0x04, System.Security.Cryptography.SHA1.HashData(issuerKey)),
			Tlv(0x02, certificate.SerialNumber.ToArray()));
	}

	public static byte[] Sha256CertificateIdOf(Certificate certificate, Certificate issuer)
	{
		return Sequence(
			Sequence(Oid("2.16.840.1.101.3.4.2.1"), [0x05, 0x00]),
			Tlv(0x04, System.Security.Cryptography.SHA256.HashData(certificate.Issuer.Span)),
			Tlv(0x04, System.Security.Cryptography.SHA256.HashData(issuer.PublicKeyInfo.PublicKey.Span)),
			Tlv(0x02, certificate.SerialNumber.ToArray()));
	}

	// The nonce extension: extnValue holds the DER of an OCTET STRING (RFC 8954).
	public static byte[] Nonce(byte[] nonce)
	{
		return Extension(NonceOid, Tlv(0x04, nonce));
	}
}
