using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.X509;

internal static class X509TestUtils
{
	public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
	public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
	public const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
	public const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
	public const string Sha512Oid = "2.16.840.1.101.3.4.2.3";
	public const string Mgf1Oid = "1.2.840.113549.1.1.8";
	public const byte Utf8StringTag = 0x0C;
	public const byte PrintableStringTag = 0x13;

	public static readonly DateTimeOffset Now = X509Time.TruncateToSeconds(DateTimeOffset.UtcNow);

	public static readonly SignatureAlgorithm[] RsaAlgorithms =
	[
		SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512,
		SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512
	];

	// The private keys of each size, generated once, so that tests do not wait for key generation.
	private static readonly ConcurrentDictionary<int, RSAParameters> RsaKeys = new();

	public static byte[] Name(string distinguishedName)
	{
		return new X500DistinguishedName(distinguishedName).RawData;
	}

	// A Name of one common name whose value has the string type of tag, which X500DistinguishedName chooses by itself.
	public static byte[] CommonName(byte tag, string value)
	{
		return Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(tag, System.Text.Encoding.UTF8.GetBytes(value)))));
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

	// A new platform key, the same for each size.
	public static RSA CreateRsa(int bits = 2048)
	{
		RSA key = RSA.Create();
		key.ImportParameters(RsaPrivateParameters(bits));
		return key;
	}

	public static RSAParameters RsaPrivateParameters(int bits = 2048)
	{
		return RsaKeys.GetOrAdd(bits, static size =>
		{
			using RSA key = RSA.Create(size);
			return key.ExportParameters(true);
		});
	}

	public static (HashAlgorithmName Hash, RSASignaturePadding Padding) RsaParametersOf(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPkcs1Sha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPkcs1Sha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPssSha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
			SignatureAlgorithm.RsaPssSha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
			SignatureAlgorithm.RsaPssSha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}

	public static X509Certificate2 BclSelfSigned(RSA key, SignatureAlgorithm algorithm, string subject = "CN=Test")
	{
		(HashAlgorithmName hash, RSASignaturePadding padding) = RsaParametersOf(algorithm);
		return new CertificateRequest(subject, key, hash, padding).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
	}

	// id-RSASSA-PSS (RFC 4055, Sec. 3.1) with RSASSA-PSS-params, whose fields are left out where null, and whose hash AlgorithmIdentifiers have NULL parameters where nullParameters is set; or without parameters.
	public static byte[] RsassaPssIdentifier(bool withParameters = true, string? hash = Sha256Oid, string? maskHash = Sha256Oid, int? saltLength = 32, int? trailerField = null, bool nullParameters = true, bool maskNullParameters = true, string maskGenerationFunction = Mgf1Oid)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier("1.2.840.113549.1.1.10");

			if (withParameters)
			{
				using (writer.PushSequence())
				{
					if (hash is not null)
					{
						using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
						{
							WriteHashIdentifier(writer, hash, nullParameters);
						}
					}

					if (maskHash is not null)
					{
						using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
						using (writer.PushSequence())
						{
							writer.WriteObjectIdentifier(maskGenerationFunction);
							WriteHashIdentifier(writer, maskHash, maskNullParameters);
						}
					}

					foreach ((int tagNumber, int? value) in (ReadOnlySpan<(int, int?)>)[(2, saltLength), (3, trailerField)])
					{
						if (value is { } integer)
						{
							using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber, true)))
							{
								writer.WriteInteger(integer);
							}
						}
					}
				}
			}
		}

		return writer.Encode();
	}

	private static void WriteHashIdentifier(AsnWriter writer, string hash, bool nullParameters)
	{
		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier(hash);

			if (nullParameters)
			{
				writer.WriteNull();
			}
		}
	}

	public static X509Extension SubjectAlternativeName(params string[] dnsNames)
	{
		SubjectAlternativeNameBuilder builder = new();

		foreach (string name in dnsNames)
		{
			if (IPAddress.TryParse(name, out IPAddress? address))
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

	// Certificates valid until 2036: self-signed RSA certificates, whose RSASSA-PSS-params have hash AlgorithmIdentifiers with NULL parameters, and an Ed25519 root and leaf.
	public static class OpenSslCertificates
	{
		// RSASSA-PSS with SHA-256 by an rsaEncryption key.
		public const string RsaPssSha256 = """
			-----BEGIN CERTIFICATE-----
			MIIDgzCCAjegAwIBAgIUECNFbiwCZAfdH+fahKDSUL11y6wwQQYJKoZIhvcNAQEK
			MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
			AKIDAgEgMB0xGzAZBgNVBAMMEk9wZW5TU0wtUFNTLVNIQTI1NjAeFw0yNjExMDEw
			MDM2MThaFw0zNjEwMjkwMDM2MThaMB0xGzAZBgNVBAMMEk9wZW5TU0wtUFNTLVNI
			QTI1NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKnDe32xyFExkBSJ
			J+UhlzMpDmWSF1Lt+tNeViN6y93j9lntyTMen7htw2wE+PLuPp+8pRewfCtlpSrb
			zUCfFpnvQYAkICEC2/H8v5GYpSUyIKxp59kZ6z1PtLr1kw0WD5WC+zeykvO/xZrp
			pquq4VVHj9yK3rtZslH3gLVaZqSy+3xhfh31NmTBE+1ImVs/WVTwOF4hliWm65J4
			PuEopSZb+Cw5uoJm/hWgXW3OiSu2CakScRYgDKJYgWFM9c33y1cTepzab2HwfNBJ
			HqWVQUsnlWCspGnaOjjoEvhtLXW6Mm0EudSQpqzt/EsoTUcPAQAlOvla2U7GLo8l
			5ghHzEUCAwEAAaNTMFEwHQYDVR0OBBYEFLz2HopzO8TsvKCgaFeihYM3NnOQMB8G
			A1UdIwQYMBaAFLz2HopzO8TsvKCgaFeihYM3NnOQMA8GA1UdEwEB/wQFMAMBAf8w
			QQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDAN
			BglghkgBZQMEAgEFAKIDAgEgA4IBAQABVGx79gpKhOfEcHMmJiS6Mk57Vncbs+U7
			a5YwqUwgNpcNtwUbhX+BsyfDLagDgjacPkx7qP7rEqS0MyvCCqHm5E7Lc58cZYgC
			H/dXRwsdLQaEGlB5hRjd0TEtYQyBGxN+k+ndxSdoy5OhOF3ZpRlVye7YskcpQVDb
			guxgs2d23aVkleQimQ7SPU7jqDAxPgQQ+Tpd/PeFqQPmVQJsqcv+LttMfXxUrhNW
			O64upaoq4ev7iNiMAbbsvVgUvJbyEEOZgDF4G4ONYkFK3ZWAB7V0vyJlVB1KhCgj
			8gGL4mCLyaViMh3Qve0LzE51tEWKeHzJSgpIhiKpX6NyAkzPqbBu
			-----END CERTIFICATE-----
			""";

		// sha384WithRSAEncryption by the same key.
		public const string RsaPkcs1Sha384 = """
			-----BEGIN CERTIFICATE-----
			MIIDHzCCAgegAwIBAgIUdmsPDQ85wbVnZoWgkVEfLpYS2TEwDQYJKoZIhvcNAQEM
			BQAwHzEdMBsGA1UEAwwUT3BlblNTTC1QS0NTMS1TSEEzODQwHhcNMjYxMTAxMDAz
			NjE4WhcNMzYxMDI5MDAzNjE4WjAfMR0wGwYDVQQDDBRPcGVuU1NMLVBLQ1MxLVNI
			QTM4NDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKnDe32xyFExkBSJ
			J+UhlzMpDmWSF1Lt+tNeViN6y93j9lntyTMen7htw2wE+PLuPp+8pRewfCtlpSrb
			zUCfFpnvQYAkICEC2/H8v5GYpSUyIKxp59kZ6z1PtLr1kw0WD5WC+zeykvO/xZrp
			pquq4VVHj9yK3rtZslH3gLVaZqSy+3xhfh31NmTBE+1ImVs/WVTwOF4hliWm65J4
			PuEopSZb+Cw5uoJm/hWgXW3OiSu2CakScRYgDKJYgWFM9c33y1cTepzab2HwfNBJ
			HqWVQUsnlWCspGnaOjjoEvhtLXW6Mm0EudSQpqzt/EsoTUcPAQAlOvla2U7GLo8l
			5ghHzEUCAwEAAaNTMFEwHQYDVR0OBBYEFLz2HopzO8TsvKCgaFeihYM3NnOQMB8G
			A1UdIwQYMBaAFLz2HopzO8TsvKCgaFeihYM3NnOQMA8GA1UdEwEB/wQFMAMBAf8w
			DQYJKoZIhvcNAQEMBQADggEBABPvwVbcHdvrIKCK01g16E0c7IhV+QyhtiZewqLM
			M3yAseFF7Rp9CRhNoQfScCRKncsc4O1xrGqL7/U5He2sDqHr/CHIymZgJ/gTbrpK
			AaRo/kAuGTRwPfzkmsYS1YI83laDsEp2x6gZF5SDQYo2hm6thOt9MQNa3ZRSnxDJ
			3yJe9mRYvMsnaV+8j1McP96AnrqgJIOhhuwBAqIWuL/8pgYAs54KIkCS65BXWdWl
			ozJ/C7Eh/KFCTuEB9G6dVTfPePAjx9Z0tOc9Wgv7jrnYX9YIJvcHJApiQi0/UNzO
			y/7E5uqhKVJ9lIEnhU/L2O5W1+Y+wzZYJD/uyo7NH9RWfh4=
			-----END CERTIFICATE-----
			""";

		// RSASSA-PSS with SHA-512 by an id-RSASSA-PSS key whose parameters name SHA-512, MGF1 with SHA-512 and a salt of 64 bytes.
		public const string RsassaPssKeySha512 = """
			-----BEGIN CERTIFICATE-----
			MIIDxTCCAnmgAwIBAgIUdsNJorrCJijrLylCwMrArcym23MwQQYJKoZIhvcNAQEK
			MDSgDzANBglghkgBZQMEAgMFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgMF
			AKIDAgFAMCQxIjAgBgNVBAMMGU9wZW5TU0wtUlNBU1NBLVBTUy1TSEE1MTIwHhcN
			MjYxMTAxMDAzNjE4WhcNMzYxMDI5MDAzNjE4WjAkMSIwIAYDVQQDDBlPcGVuU1NM
			LVJTQVNTQS1QU1MtU0hBNTEyMIIBVjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFl
			AwQCAwUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAwUAogMCAUADggEPADCC
			AQoCggEBAKHx/pYzLHlBiBWhYvqj8vZatnMXIapTFSs5f8gy5gUdSTS79j+E1cWk
			Qxj7MlfbbRjWOpPobCQddCQEBogrQmM/9kj5R1IjYIXzH2A0UmPxZDaAWfDfc6x4
			9YCMrLJ0ECnFDz/wjxx84svF6ECp6XB8FKZXnyieJHU30cZkldnIb6QLK/NMty70
			U2vXu1dadY0eHW6uaTb3C68hk4dcQt5+QmH9/5oYPYObFTcPM9FpF9j8YOYPTaze
			PEjZnqxSl1RbwsFQSnIrWDAcf706MqJZo8/ggkTG2xyjsHqSXA8vixEJioILOuU9
			G+mFdZfVpB+wwbAnXK8ymUTgvaJi7pECAwEAAaNTMFEwHQYDVR0OBBYEFIChNRrk
			0+1J4cBqKhT6IlQcKB3bMB8GA1UdIwQYMBaAFIChNRrk0+1J4cBqKhT6IlQcKB3b
			MA8GA1UdEwEB/wQFMAMBAf8wQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgMF
			AKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgMFAKIDAgFAA4IBAQBKMnJYSR16
			qlW51OzK3CdcsMCvWFP/MpZ5ULZbJZA8lYBAdqW+iPuFGFC7O4QaTol2VdLiTbi+
			wOk0YubQqdQ670z8hjchIDBMoW6Q/otjizvpU5ndQujJQG5M+/5bDj1RaL5ZptYI
			Vxo8JAqN0omNBTncLQOzGDNidsRlpwosnZ4vqXulVD3ltCv4mrJyvcSGPEnCJxcz
			sF/WcuqXA2xxhPEUNbzwFmtlOtEvTvXS5Q+viZ3y4q3lyDbjytsZYey4echUeVZZ
			1JFUXqDR9jTDBdoxwH5j0hz9hwne51qf0HQ4OVuE0DZB7lxLUmzNtVOWRSe9HoRX
			XgZSkcN1xzGr
			-----END CERTIFICATE-----
			""";

		// RSASSA-PSS with SHA-384 by an id-RSASSA-PSS key without parameters.
		public const string RsassaPssKeyWithoutParametersSha384 = """
			-----BEGIN CERTIFICATE-----
			MIIDgTCCAjWgAwIBAgIUZkNRhnuqdbr8KwM2WRSloYgkf+QwQQYJKoZIhvcNAQEK
			MDSgDzANBglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIF
			AKIDAgEwMB0xGzAZBgNVBAMMEk9wZW5TU0wtUlNBU1NBLVBTUzAeFw0yNjExMDEw
			MDM2MThaFw0zNjEwMjkwMDM2MThaMB0xGzAZBgNVBAMMEk9wZW5TU0wtUlNBU1NB
			LVBTUzCCASAwCwYJKoZIhvcNAQEKA4IBDwAwggEKAoIBAQDHUr4eb92LY4AqMxC6
			0fk7AX3Hdjvy2cgjE0RYcOSuDZcat4zXhawwaZTSK55iwcpAM/nDoxbMy8qX5Dh+
			OHqekv571p0B4hSOgplgUwJDyaRSiBT/dONSOrtASxP9K+2gPkFZC93axSuaOLXI
			eOHa+fDa1xPSPx68K2PXbDS5Ag46WF+4OWLstODRHrn0kZPcm/xGsH6g057FC6mW
			Ayo2e0JO5RlrkXsTAi5xNejr3Ick28KyJ7Nsvk0acIY/EcX2NEKI/M8pP14kEjpr
			2i2fXnyc/IswYsRT0aKGIZ5tWisbyCAEiBizcOs8DTmZ+vziBy/mg5x9c2sL5pwQ
			Yqo3AgMBAAGjUzBRMB0GA1UdDgQWBBQsi1FrbMGBRnq3zIzSfV7gn8Y/5zAfBgNV
			HSMEGDAWgBQsi1FrbMGBRnq3zIzSfV7gn8Y/5zAPBgNVHRMBAf8EBTADAQH/MEEG
			CSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJ
			YIZIAWUDBAICBQCiAwIBMAOCAQEAH88nBD0tlUUlUwbkLmmIzIwO1gDV/PWJ2cCV
			48ybAdmjKD+SWSwGJwpzLbBrCxXPvaE9DBP/YevttVWgGngN6773Qnos8WAk+r0W
			PeASgecmyfUrvIMUJTphEkp2zdaexocgrTNjP/YCRE6Lbbdy990WmiVDZ5odkYw6
			+ii66pc0Oe1VXywWNRdTQ2/IUJKTt9NV3yY7CH+S4piJbPPQ9dU+h2tBBajgMdkh
			/PepijOW/JDbbTNn8XSQHYlFne1cVZfoGPECCRQkPKQvqTsNX7ofju17Z4mSJ0Q3
			KPI0PCwVVfgntapKVkjI+Nr2gA0ZpeayAXQUv5N7MQ8jaxLMvg==
			-----END CERTIFICATE-----
			""";

		// A self-signed Ed25519 root with critical basic constraints that assert cA, a critical key usage of keyCertSign and cRLSign, and a subject key identifier.
		public const string Ed25519Root = """
			-----BEGIN CERTIFICATE-----
			MIIBQTCB9KADAgECAhRSsMChHTV5vmF0ov1X/6u8K5IXmzAFBgMrZXAwHzEdMBsG
			A1UEAwwUT3BlblNTTCBFZDI1NTE5IFJvb3QwHhcNMjYxMTAyMDgzOTU5WhcNMzYx
			MDMwMDgzOTU5WjAfMR0wGwYDVQQDDBRPcGVuU1NMIEVkMjU1MTkgUm9vdDAqMAUG
			AytlcAMhAOucB59Pm68J206TQiZ5ob3z0NiF9+GmQiQJYmQ5FZX9o0IwQDAPBgNV
			HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUA0X0BWC0qjNl
			tDhIfuw7UsdTF78wBQYDK2VwA0EA0wG+OGPye3By7Kfcez69PavtXKW2vdaX2wvw
			4PxY7KXgQGmflxowZ6c+mn93opWWgYbltD4naR5vr5wX/SRaCg==
			-----END CERTIFICATE-----
			""";

		// An Ed25519 leaf that the root signs, for the DNS name example.com and id-kp-serverAuth, with a critical key usage of digitalSignature.
		public const string Ed25519Leaf = """
			-----BEGIN CERTIFICATE-----
			MIIBjzCCAUGgAwIBAgIUIt4kuGxQSU4tELAO6YOZvMWNDZQwBQYDK2VwMB8xHTAb
			BgNVBAMMFE9wZW5TU0wgRWQyNTUxOSBSb290MB4XDTI2MTEwMjA4Mzk1OVoXDTM2
			MTAzMDA4Mzk1OVowHzEdMBsGA1UEAwwUT3BlblNTTCBFZDI1NTE5IExlYWYwKjAF
			BgMrZXADIQAKDnARRID+EDfxJoWPxZNRKZdtOH2f9CJiM3dnW0PHPaOBjjCBizAM
			BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
			ATAWBgNVHREEDzANggtleGFtcGxlLmNvbTAdBgNVHQ4EFgQUPhZSRdp+LNe3QLl2
			HiV8i7k5VsowHwYDVR0jBBgwFoAUA0X0BWC0qjNltDhIfuw7UsdTF78wBQYDK2Vw
			A0EADnympdDvHmHNgCtUGaHyZAzGpS90vOZAf0YrjuB1wHH5NDqr5dMdylayfFeD
			VeTpOkdiRR3yKJuHygbiC87+Aw==
			-----END CERTIFICATE-----
			""";
	}

	public static class ExternalCertificates
	{
		public const string Ed448Root = """
			-----BEGIN CERTIFICATE-----
			MIIBZTCB5qADAgECAgEBMAUGAytlcTAVMRMwEQYDVQQDDApFZDQ0OCBSb290MB4X
			DTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowFTETMBEGA1UEAwwKRWQ0NDgg
			Um9vdDBDMAUGAytlcQM6AALn+iBOGvlpQqkoTbMZ9WP0KUQNO4xaR3qOtCIKPefM
			1X/XRpsaTdGufRFsDJtFKiuWBoDTgSJiAKNCMEAwDwYDVR0TAQH/BAUwAwEB/zAO
			BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFIEv5/t9ujcI347q5sBJH+SG+nR7MAUG
			AytlcQNzADPQgdTGIFsZ78F6muK+UJ6X0gNQH/bt2J9rfYUKKCLHZBeegtFuGwwl
			OQSOAqphm0qQAIHufmGrgIf5NOeuH4+RsZWYYRTzqn7rXJMpub69PmkHaxGS4kHI
			qAw/wLr+ebw7v6o/u0G1BvaLlCkM5J0YAA==
			-----END CERTIFICATE-----
			""";

		public const string Ed448Leaf = """
			-----BEGIN CERTIFICATE-----
			MIIBszCCATOgAwIBAgIBAjAFBgMrZXEwFTETMBEGA1UEAwwKRWQ0NDggUm9vdDAe
			Fw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBUxEzARBgNVBAMMCkVkNDQ4
			IExlYWYwQzAFBgMrZXEDOgBYdbwRc0amQ3kKbDYkVCLjM5G47B/PHwjaRu7sZVvP
			M75m0bl0RSoaX1OioM733gUAsCzBKSlyiYCjgY4wgYswDAYDVR0TAQH/BAIwADAO
			BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFgYDVR0RBA8wDYIL
			ZXhhbXBsZS5jb20wHQYDVR0OBBYEFEMbBkUXM1b0nGPxppu4ZMZw7oayMB8GA1Ud
			IwQYMBaAFIEv5/t9ujcI347q5sBJH+SG+nR7MAUGAytlcQNzAJRwGriNOhlqrGEU
			PYamNYaAQIV/T8c4HBH+LvXNdJh/k31e4Bgnz7Fqc/E5EwDaFLpYUzdrBsu3AMmh
			LMX+XMC7bAeYRzbtYWEEkcyoWM8M3XYlhaXfqW9/Lfe5gtoyHXHrfNZjg/badk5M
			/7ArucoJAA==
			-----END CERTIFICATE-----
			""";
	}

	// A dNSName with the bytes of the string as they are, so that the tests can make entries that SubjectAlternativeNameBuilder refuses.
	public static byte[] DnsName(string name)
	{
		return Tlv(0x82, System.Text.Encoding.Latin1.GetBytes(name));
	}

	public static byte[] IPAddressName(string address)
	{
		return Tlv(0x87, IPAddress.Parse(address).GetAddressBytes());
	}

	// The value of a subject alternative name extension that holds the names.
	public static byte[] GeneralNames(params byte[][] names)
	{
		return Sequence(names);
	}

	// A certificate of CertificateParts with the extensions, each the DER of an Extension.
	public static Certificate WithExtensions(params byte[][] extensions)
	{
		return Certificate.Decode((new CertificateParts() with { AfterSubjectPublicKeyInfo = [Extensions(extensions)] }).Encode());
	}

	// NameConstraints (RFC 5280, Sec. 4.2.1.10) with one dNSName subtree, permitted or excluded.
	public static X509Extension NameConstraints(string dnsName, bool excluded = false)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, excluded ? 1 : 0, true)))
		using (writer.PushSequence())
		{
			writer.WriteCharacterString(UniversalTagNumber.IA5String, dnsName, new Asn1Tag(TagClass.ContextSpecific, 2));
		}

		return new X509Extension("2.5.29.30", writer.Encode(), true);
	}

	public sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
	{
		public override DateTimeOffset GetUtcNow()
		{
			return now;
		}
	}

	// A loopback server that accepts connections and never answers, as an unreachable responder would, without the network.
	public sealed class SilentServer : IDisposable
	{
		private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
		private readonly List<Socket> _sockets = [];
		private int _connections;

		public SilentServer()
		{
			_listener.Start();
			_ = AcceptAsync();
		}

		public int Connections => Volatile.Read(ref _connections);

		public string Url(string path)
		{
			return $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/{path}";
		}

		public void Dispose()
		{
			_listener.Stop();

			lock (_sockets)
			{
				foreach (Socket socket in _sockets)
				{
					socket.Dispose();
				}
			}
		}

		private async Task AcceptAsync()
		{
			try
			{
				while (true)
				{
					Socket socket = await _listener.AcceptSocketAsync();
					Interlocked.Increment(ref _connections);

					lock (_sockets)
					{
						_sockets.Add(socket);
					}
				}
			}
			catch (SocketException)
			{
			}
			catch (ObjectDisposedException)
			{
			}
		}
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
