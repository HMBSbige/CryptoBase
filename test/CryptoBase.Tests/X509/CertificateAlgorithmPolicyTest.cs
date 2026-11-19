using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.X509;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class CertificateAlgorithmPolicyTest
{
	private const string RsassaPssOid = "1.2.840.113549.1.1.10";
	private const string ECPublicKeyOid = "1.2.840.10045.2.1";
	private const string Md2Oid = "1.2.840.113549.2.2";
	private const string Md4Oid = "1.2.840.113549.2.4";
	private const string Md5Oid = "1.2.840.113549.2.5";
	private const string Sha0Oid = "1.3.14.3.2.18";
	private const string OiwDirectoryMd2Oid = "1.3.14.7.2.2.1";
	private const string Sha1Oid = "1.3.14.3.2.26";
	private const string Sha224Oid = "2.16.840.1.101.3.4.2.4";
	private const string EcdsaWithSpecifiedOid = "1.2.840.10045.4.3";

	private static readonly byte[] RsaEncryption = Sequence(Oid("1.2.840.113549.1.1.1"), [0x05, 0x00]);
	private static readonly byte[] RsassaPss = Sequence(Oid(RsassaPssOid));
	private static readonly BigInteger F4 = 65537;

	// Each type, from the importers' own encodings and the example certificates of SM2 and RFC 9881, each of which SignatureKey imports.
	[Test]
	public async Task KeyAlgorithmNamesEachType()
	{
		RSAParameters rsa = RsaPrivateParameters();
		BigInteger modulus = new(rsa.Modulus, isUnsigned: true, isBigEndian: true);
		BigInteger exponent = new(rsa.Exponent, isUnsigned: true, isBigEndian: true);
		using EcdsaP256 p256 = EcdsaP256.GenerateKey();
		using EcdsaP384 p384 = EcdsaP384.GenerateKey();
		using EcdsaP521 p521 = EcdsaP521.GenerateKey();
		using Ed25519 ed25519 = Ed25519.GenerateKey();
		using Ed448 ed448 = Ed448.GenerateKey();

		(string Name, byte[] SubjectPublicKeyInfo, PublicKeyAlgorithm Expected)[] cases =
		[
			("rsaEncryption", RsaSubjectPublicKeyInfo(modulus, exponent), PublicKeyAlgorithm.Rsa),
			("id-RSASSA-PSS without parameters", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPss), PublicKeyAlgorithm.RsaPss),
			("id-RSASSA-PSS with SHA-256", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier()), PublicKeyAlgorithm.RsaPss),
			("id-RSASSA-PSS with SHA-512 and a shorter salt", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier(hash: Sha512Oid, maskHash: Sha512Oid, saltLength: 0)), PublicKeyAlgorithm.RsaPss),
			("P-256", ExportSubjectPublicKeyInfo(p256), PublicKeyAlgorithm.EcdsaP256),
			("P-384", ExportSubjectPublicKeyInfo(p384), PublicKeyAlgorithm.EcdsaP384),
			("P-521", ExportSubjectPublicKeyInfo(p521), PublicKeyAlgorithm.EcdsaP521),
			("SM2", ReadCertificate("sm2-leaf.pem").PublicKeyInfo.Encoded.ToArray(), PublicKeyAlgorithm.SM2),
			("Ed25519", ExportSubjectPublicKeyInfo(ed25519), PublicKeyAlgorithm.Ed25519),
			("Ed448", ExportSubjectPublicKeyInfo(ed448), PublicKeyAlgorithm.Ed448),
			("ML-DSA-44", ReadCertificate("rfc9881-mldsa44.pem").PublicKeyInfo.Encoded.ToArray(), PublicKeyAlgorithm.MLDsa44),
			("ML-DSA-65", ReadCertificate("rfc9881-mldsa65.pem").PublicKeyInfo.Encoded.ToArray(), PublicKeyAlgorithm.MLDsa65),
			("ML-DSA-87", ReadCertificate("rfc9881-mldsa87.pem").PublicKeyInfo.Encoded.ToArray(), PublicKeyAlgorithm.MLDsa87)
		];

		using (Assert.Multiple())
		{
			foreach ((string name, byte[] subjectPublicKeyInfo, PublicKeyAlgorithm expected) in cases)
			{
				await Assert.That(SubjectPublicKeyInfo.Decode(subjectPublicKeyInfo).KeyAlgorithm).IsEqualTo(expected).Because(name);

				using ISignatureKey key = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
			}

			using PlatformRsaKey platformRsa = PlatformRsaKey.ImportSubjectPublicKeyInfo(cases[2].SubjectPublicKeyInfo);
		}
	}

	// Other algorithms and curves, and the known algorithms with parameters that the importers refuse.
	[Test]
	public async Task KeyAlgorithmIsUnknownOtherwise()
	{
		RSAParameters rsa = RsaPrivateParameters();
		BigInteger modulus = new(rsa.Modulus, isUnsigned: true, isBigEndian: true);
		BigInteger exponent = new(rsa.Exponent, isUnsigned: true, isBigEndian: true);
		using EcdsaP256 p256 = EcdsaP256.GenerateKey();
		byte[] point = SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(p256)).PublicKey.ToArray();
		using Ed25519 ed25519 = Ed25519.GenerateKey();
		byte[] edPoint = SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(ed25519)).PublicKey.ToArray();

		(string Name, byte[] SubjectPublicKeyInfo, bool Rsa)[] cases =
		[
			("rsaEncryption without parameters", RsaSubjectPublicKeyInfo(modulus, exponent, Sequence(Oid("1.2.840.113549.1.1.1"))), true),
			("rsaEncryption with other parameters", RsaSubjectPublicKeyInfo(modulus, exponent, Sequence(Oid("1.2.840.113549.1.1.1"), [0x04, 0x00])), true),
			("id-RSASSA-PSS with NULL parameters", RsaSubjectPublicKeyInfo(modulus, exponent, Sequence(Oid(RsassaPssOid), [0x05, 0x00])), true),
			("id-RSASSA-PSS with SHA-1", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier(hash: Sha1Oid, maskHash: Sha1Oid, saltLength: 20)), true),
			("id-RSASSA-PSS with the default SHA-1", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier(hash: null, maskHash: null, saltLength: null)), true),
			("id-RSASSA-PSS with MGF1 of another hash", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier(maskHash: Sha384Oid)), true),
			("id-RSASSA-PSS with a salt longer than the hash", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier(saltLength: 33)), true),
			("id-RSASSA-PSS with trailer field 2", RsaSubjectPublicKeyInfo(modulus, exponent, RsassaPssIdentifier(trailerField: 2)), true),
			("secp256k1", Sequence(Sequence(Oid(ECPublicKeyOid), Oid("1.3.132.0.10")), Tlv(0x03, [0x00], point)), false),
			("explicit curve", Sequence(Sequence(Oid(ECPublicKeyOid), Sequence([0x02, 0x01, 0x01])), Tlv(0x03, [0x00], point)), false),
			("id-ecPublicKey without parameters", Sequence(Sequence(Oid(ECPublicKeyOid)), Tlv(0x03, [0x00], point)), false),
			("id-ecPublicKey with NULL parameters", Sequence(Sequence(Oid(ECPublicKeyOid), [0x05, 0x00]), Tlv(0x03, [0x00], point)), false),
			("P-256 as the algorithm", Sequence(Sequence(Oid("1.2.840.10045.3.1.7")), Tlv(0x03, [0x00], point)), false),
			("DSA", Sequence(Sequence(Oid("1.2.840.10040.4.1"), Sequence([0x02, 0x01, 0x03], [0x02, 0x01, 0x05], [0x02, 0x01, 0x07])), Tlv(0x03, [0x00, 0x02, 0x01, 0x09])), false),
			("X25519", Sequence(Sequence(Oid("1.3.101.110")), Tlv(0x03, [0x00], edPoint)), false),
			("X448", Sequence(Sequence(Oid("1.3.101.111")), Tlv(0x03, [0x00, .. new byte[56]])), false),
			("Ed25519 with NULL parameters", Sequence(Sequence(Oid("1.3.101.112"), [0x05, 0x00]), Tlv(0x03, [0x00], edPoint)), false),
			("ML-DSA-44 with NULL parameters", Sequence(Sequence(Oid("2.16.840.1.101.3.4.3.17"), [0x05, 0x00]), Tlv(0x03, [0x00, .. new byte[1312]])), false),
			("an unknown algorithm", Sequence(Sequence(Oid("1.2.3.4")), Tlv(0x03, [0x00])), false)
		];

		using (Assert.Multiple())
		{
			foreach ((string name, byte[] subjectPublicKeyInfo, bool isRsa) in cases)
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.Decode(subjectPublicKeyInfo);
				await Assert.That(info.KeyAlgorithm).IsEqualTo(PublicKeyAlgorithm.Unknown).Because(name);
				await Assert.That(info.GetRsaKeySize()).IsNull().Because(name);
				await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<Exception>().Because(name);

				if (isRsa)
				{
					await Assert.That(() => PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<Exception>().Because(name);
				}
			}
		}
	}

	[Test]
	[Arguments(1024)]
	[Arguments(2047)]
	[Arguments(2048)]
	[Arguments(3072)]
	[Arguments(16392)]
	public async Task GetRsaKeySizeCountsTheBitsOfTheModulus(int bits)
	{
		using (Assert.Multiple())
		{
			await Assert.That(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(Modulus(bits), F4)).GetRsaKeySize()).IsEqualTo(bits);
			await Assert.That(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(Modulus(bits), F4, RsassaPss)).GetRsaKeySize()).IsEqualTo(bits);

			// The exponent is not checked.
			await Assert.That(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(Modulus(bits), -F4)).GetRsaKeySize()).IsEqualTo(bits);
		}
	}

	[Test]
	public async Task GetRsaKeySizeIsNullForOtherKeys()
	{
		using EcdsaP256 p256 = EcdsaP256.GenerateKey();
		using Ed25519 ed25519 = Ed25519.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That(SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(p256)).GetRsaKeySize()).IsNull();
			await Assert.That(SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(ed25519)).GetRsaKeySize()).IsNull();
			await Assert.That(ReadCertificate("sm2-leaf.pem").PublicKeyInfo.GetRsaKeySize()).IsNull();
		}
	}

	[Test]
	public async Task GetRsaKeySizeThrowsForMalformedKeys()
	{
		byte[] modulus = Integer(Modulus(2048));
		byte[] exponent = Integer(F4);

		(string Name, byte[] RsaPublicKey)[] cases =
		[
			("not a SEQUENCE", [0x05, 0x00]),
			("empty", []),
			("one INTEGER", Sequence(modulus)),
			("a third INTEGER", Sequence(modulus, exponent, exponent)),
			("a trailing byte", [.. Sequence(modulus, exponent), 0x00]),
			("long-form length", WithRedundantLengthByte(Sequence(modulus, exponent))),
			("negative modulus", Sequence(Integer(-Modulus(2048)), exponent)),
			("zero modulus", Sequence(Integer(BigInteger.Zero), exponent)),
			("OCTET STRING modulus", Sequence(Tlv(0x04, [0x01]), exponent))
		];

		using (Assert.Multiple())
		{
			foreach ((string name, byte[] rsaPublicKey) in cases)
			{
				SubjectPublicKeyInfo rsa = SubjectPublicKeyInfo.Decode(Sequence(RsaEncryption, Tlv(0x03, [0x00], rsaPublicKey)));
				SubjectPublicKeyInfo rsassaPss = SubjectPublicKeyInfo.Decode(Sequence(RsassaPss, Tlv(0x03, [0x00], rsaPublicKey)));
				await Assert.That(() => rsa.GetRsaKeySize()).Throws<CryptographicException>().Because(name);
				await Assert.That(() => rsassaPss.GetRsaKeySize()).Throws<CryptographicException>().Because(name);
			}
		}
	}

	// The algorithms of AlgorithmIdentifier.TryGetSignatureAlgorithm, in every encoding that it accepts.
	[Test]
	public async Task SignatureStrengthIsAcceptableForSupportedAlgorithms()
	{
		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[.. RsaAlgorithms, SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.EcdsaSha384, SignatureAlgorithm.EcdsaSha512, SignatureAlgorithm.Ed25519, SignatureAlgorithm.Ed448, SignatureAlgorithm.MLDsa44, SignatureAlgorithm.MLDsa65, SignatureAlgorithm.MLDsa87, SignatureAlgorithm.SM2SM3])
			{
				await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(AlgorithmIdentifier.FromSignatureAlgorithm(algorithm))).IsEqualTo(CertificateSignatureStrength.Acceptable).Because(algorithm.ToString());
			}

			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid("1.2.840.113549.1.1.11"))))).IsEqualTo(CertificateSignatureStrength.Acceptable);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid("1.2.156.10197.1.501"), [0x05, 0x00])))).IsEqualTo(CertificateSignatureStrength.Acceptable);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(RsassaPssIdentifier(nullParameters: false, maskNullParameters: false, trailerField: 1)))).IsEqualTo(CertificateSignatureStrength.Acceptable);
		}
	}

	// MD2, MD4, MD5 and SHA-0 are forbidden, SHA-1, SHA-224 and DSA with another hash weak, with or without NULL parameters.
	[Test]
	[Arguments("1.2.840.113549.1.1.2", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.2.840.113549.1.1.3", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.2.840.113549.1.1.4", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.2", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.3", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.4", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.24", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.25", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.13", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.15", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.3.2.21", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.3.14.7.2.3.1", CertificateSignatureStrength.Forbidden)]
	[Arguments("1.2.840.113549.1.1.5", CertificateSignatureStrength.Weak)]
	[Arguments("1.2.840.113549.1.1.14", CertificateSignatureStrength.Weak)]
	[Arguments("1.3.14.3.2.29", CertificateSignatureStrength.Weak)]
	[Arguments("1.2.840.10045.4.1", CertificateSignatureStrength.Weak)]
	[Arguments("1.2.840.10045.4.3.1", CertificateSignatureStrength.Weak)]
	[Arguments("1.2.840.10040.4.3", CertificateSignatureStrength.Weak)]
	[Arguments("1.3.14.3.2.27", CertificateSignatureStrength.Weak)]
	[Arguments("1.3.14.3.2.28", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.1", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.2", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.3", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.4", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.5", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.6", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.7", CertificateSignatureStrength.Weak)]
	[Arguments("2.16.840.1.101.3.4.3.8", CertificateSignatureStrength.Weak)]
	[Arguments("1.2.840.113549.1.1.15", CertificateSignatureStrength.Unsupported)]
	[Arguments("2.16.840.1.101.3.4.3.14", CertificateSignatureStrength.Unsupported)]
	[Arguments("1.2.3.4", CertificateSignatureStrength.Unsupported)]
	public async Task ClassifiesSignatureAlgorithms(string oid, CertificateSignatureStrength expected)
	{
		using (Assert.Multiple())
		{
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid(oid))))).IsEqualTo(expected);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid(oid), [0x05, 0x00])))).IsEqualTo(expected);
		}
	}

	// Algorithms that are supported only with other parameters are unsupported with these.
	[Test]
	public async Task ClassifiesSupportedAlgorithmsWithOtherParametersAsUnsupported()
	{
		using (Assert.Multiple())
		{
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid("1.3.101.112"), [0x05, 0x00])))).IsEqualTo(CertificateSignatureStrength.Unsupported);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid("1.2.840.10045.4.3.2"), [0x05, 0x00])))).IsEqualTo(CertificateSignatureStrength.Unsupported);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid("1.2.840.113549.1.1.11"), [0x04, 0x00])))).IsEqualTo(CertificateSignatureStrength.Unsupported);
		}
	}

	// RSASSA-PSS by its hash and MGF1 hash, the most severe one standing; the hash and the MGF1 hash default to SHA-1 (RFC 4055, Sec. 3.1).
	[Test]
	[Arguments(true, Sha256Oid, Sha256Oid, 32, CertificateSignatureStrength.Acceptable)]
	[Arguments(true, Sha512Oid, Sha512Oid, 64, CertificateSignatureStrength.Acceptable)]
	[Arguments(false, null, null, null, CertificateSignatureStrength.Weak)]
	[Arguments(true, null, null, null, CertificateSignatureStrength.Weak)]
	[Arguments(true, null, Sha256Oid, 32, CertificateSignatureStrength.Weak)]
	[Arguments(true, Sha256Oid, null, 32, CertificateSignatureStrength.Weak)]
	[Arguments(true, Sha1Oid, Sha1Oid, 20, CertificateSignatureStrength.Weak)]
	[Arguments(true, Sha256Oid, Sha1Oid, 32, CertificateSignatureStrength.Weak)]
	[Arguments(true, Sha224Oid, Sha224Oid, 28, CertificateSignatureStrength.Weak)]
	[Arguments(true, Sha256Oid, Sha224Oid, 32, CertificateSignatureStrength.Weak)]
	[Arguments(true, Md5Oid, Md5Oid, 16, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Md5Oid, Sha256Oid, 32, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Md5Oid, Sha1Oid, 20, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Md5Oid, null, 20, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Sha1Oid, Md5Oid, 20, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Sha256Oid, Md2Oid, 32, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Md4Oid, Sha256Oid, 32, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Sha0Oid, Sha256Oid, 32, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Sha256Oid, OiwDirectoryMd2Oid, 32, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Sha256Oid, Sha0Oid, 32, CertificateSignatureStrength.Forbidden)]
	[Arguments(true, Sha256Oid, Sha256Oid, 20, CertificateSignatureStrength.Unsupported)]
	[Arguments(true, Sha256Oid, Sha384Oid, 32, CertificateSignatureStrength.Unsupported)]
	[Arguments(true, "2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.2.8", 32, CertificateSignatureStrength.Unsupported)]
	public async Task ClassifiesRsassaPssParameters(bool withParameters, string? hash, string? maskHash, int? saltLength, CertificateSignatureStrength expected)
	{
		AlgorithmIdentifier identifier = Identifier(RsassaPssIdentifier(withParameters: withParameters, hash: hash, maskHash: maskHash, saltLength: saltLength));

		await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(identifier)).IsEqualTo(expected);
	}

	// A mask generation function other than MGF1 names no hash, so only the hash counts.
	[Test]
	public async Task ClassifiesRsassaPssWithAnotherMaskGenerationFunction()
	{
		using (Assert.Multiple())
		{
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(RsassaPssIdentifier(maskGenerationFunction: "1.2.3.4")))).IsEqualTo(CertificateSignatureStrength.Unsupported);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(RsassaPssIdentifier(hash: Sha1Oid, maskGenerationFunction: "1.2.3.4")))).IsEqualTo(CertificateSignatureStrength.Weak);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(RsassaPssIdentifier(hash: Md5Oid, maskGenerationFunction: "1.2.3.4")))).IsEqualTo(CertificateSignatureStrength.Forbidden);
		}
	}

	// Parameters that are present but are not RSASSA-PSS-params could name MD5 to another reader, even after a hash that is not weak:
	// NULL, a field that does not decode, one under its tag with another value after it, fields out of order, or anything after the last.
	// Absent parameters are Weak, as ClassifiesRsassaPssParameters shows: their hashes are SHA-1 by default.
	[Test]
	public async Task ClassifiesRsassaPssParametersThatDoNotDecodeAsForbidden()
	{
		byte[] sha256Identifier = Sequence(Oid(Sha256Oid), [0x05, 0x00]);
		byte[] sha256 = Tlv(0xA0, sha256Identifier);
		byte[] mgf1Sha256 = Tlv(0xA1, Sequence(Oid(Mgf1Oid), sha256Identifier));

		byte[][] parameters =
		[
			[0x05, 0x00],
			Tlv(0xA0, [0x05, 0x00]),
			Sequence(Tlv(0xA0, [0x05, 0x00])),
			Sequence(Tlv(0xA0, Sequence([0x05, 0x00]))),
			Sequence(Tlv(0xA0, Sequence([0x02, 0x01, 0x00]))),
			Sequence(sha256, Tlv(0xA1, Sequence(Oid(Mgf1Oid), [0x05, 0x00]))),
			Sequence(sha256, Tlv(0xA1, Sequence(Oid(Mgf1Oid)))),
			Sequence(sha256, Tlv(0xA1, [0x05, 0x00])),
			Sequence(sha256, Tlv(0xA1, Sequence([0x05, 0x00]))),
			Sequence(Tlv(0xA0, sha256Identifier, [0x05, 0x00]), mgf1Sha256),
			Sequence(Tlv(0xA0, Sequence(Oid(Sha256Oid), [0x05, 0x00], [0x05, 0x00])), mgf1Sha256),
			Sequence(sha256, Tlv(0xA1, Sequence(Oid(Mgf1Oid), sha256Identifier, [0x05, 0x00]))),
			Sequence(mgf1Sha256, sha256),
			Sequence(sha256, mgf1Sha256, Tlv(0xA2, [0x05, 0x00])),
			Sequence(sha256, mgf1Sha256, Tlv(0xA3, [0x02, 0x01, 0x01]), Tlv(0xA2, [0x02, 0x01, 0x20])),
			Sequence(sha256, mgf1Sha256, [0x05, 0x00])
		];

		using (Assert.Multiple())
		{
			foreach (byte[] value in parameters)
			{
				await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid(RsassaPssOid), value)))).IsEqualTo(CertificateSignatureStrength.Forbidden).Because(Convert.ToHexString(value));
			}

			await Assert.That(() => CertificateAlgorithmPolicy.GetSignatureStrength(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// ecdsa-with-Specified (ANSI X9.62) by the hash that its parameters name, whose AlgorithmIdentifier may have NULL or absent parameters.
	[Test]
	[Arguments(Md2Oid, CertificateSignatureStrength.Forbidden)]
	[Arguments(Md4Oid, CertificateSignatureStrength.Forbidden)]
	[Arguments(Md5Oid, CertificateSignatureStrength.Forbidden)]
	[Arguments(Sha0Oid, CertificateSignatureStrength.Forbidden)]
	[Arguments(OiwDirectoryMd2Oid, CertificateSignatureStrength.Forbidden)]
	[Arguments(Sha1Oid, CertificateSignatureStrength.Weak)]
	[Arguments(Sha224Oid, CertificateSignatureStrength.Weak)]
	[Arguments(Sha256Oid, CertificateSignatureStrength.Unsupported)]
	[Arguments(Sha512Oid, CertificateSignatureStrength.Unsupported)]
	public async Task ClassifiesEcdsaWithSpecifiedByItsHash(string hash, CertificateSignatureStrength expected)
	{
		using (Assert.Multiple())
		{
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid(EcdsaWithSpecifiedOid), Sequence(Oid(hash), [0x05, 0x00]))))).IsEqualTo(expected);
			await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(Sequence(Oid(EcdsaWithSpecifiedOid), Sequence(Oid(hash)))))).IsEqualTo(expected);
		}
	}

	// Parameters that are absent or are not an AlgorithmIdentifier alone name no hash that the signature is known to use, and could name MD5 to another reader.
	[Test]
	public async Task ClassifiesEcdsaWithSpecifiedParametersThatDoNotDecodeAsForbidden()
	{
		byte[] sha256Identifier = Sequence(Oid(Sha256Oid), [0x05, 0x00]);

		(string Name, byte[] Identifier)[] cases =
		[
			("no parameters", Sequence(Oid(EcdsaWithSpecifiedOid))),
			("NULL", Sequence(Oid(EcdsaWithSpecifiedOid), [0x05, 0x00])),
			("an OBJECT IDENTIFIER alone", Sequence(Oid(EcdsaWithSpecifiedOid), Oid(Sha256Oid))),
			("an empty SEQUENCE", Sequence(Oid(EcdsaWithSpecifiedOid), Sequence())),
			("a SEQUENCE without an OBJECT IDENTIFIER", Sequence(Oid(EcdsaWithSpecifiedOid), Sequence([0x05, 0x00]))),
			("an OCTET STRING", Sequence(Oid(EcdsaWithSpecifiedOid), Tlv(0x04, sha256Identifier))),
			("a second value after the parameters of the hash", Sequence(Oid(EcdsaWithSpecifiedOid), Sequence(Oid(Sha256Oid), [0x05, 0x00], [0x05, 0x00]))),
			("a second value after MD5's parameters", Sequence(Oid(EcdsaWithSpecifiedOid), Sequence(Oid(Md5Oid), [0x05, 0x00], [0x05, 0x00]))),
			("a SEQUENCE of two AlgorithmIdentifiers", Sequence(Oid(EcdsaWithSpecifiedOid), Sequence(sha256Identifier, sha256Identifier)))
		];

		using (Assert.Multiple())
		{
			foreach ((string name, byte[] identifier) in cases)
			{
				await Assert.That(CertificateAlgorithmPolicy.GetSignatureStrength(Identifier(identifier))).IsEqualTo(CertificateSignatureStrength.Forbidden).Because(name);
			}
		}
	}

	// The bounds of 16384 bits for the modulus and 33 for the public exponent, which must make a valid key (RFC 8017, Sec. 3.1), for rsaEncryption and id-RSASSA-PSS whatever their parameters.
	[Test]
	public async Task BoundsTheVerificationOfRsaKeys()
	{
		BigInteger modulus = Modulus(2048);

		(string Name, BigInteger Modulus, BigInteger Exponent, bool Expected)[] cases =
		[
			("2048 bits", modulus, F4, true),
			("16384 bits", Modulus(16384), F4, true),
			("16392 bits", Modulus(16392), F4, false),
			("1024 bits", Modulus(1024), F4, true),
			("2052 bits", Modulus(2052), F4, true),
			("exponent 3", modulus, 3, true),
			("33-bit exponent", modulus, (BigInteger.One << 33) - 1, true),
			("34-bit exponent", modulus, (BigInteger.One << 33) + 1, false),
			("even exponent", modulus, 65536, false),
			("exponent 1", modulus, 1, false),
			("zero exponent", modulus, 0, false),
			("even modulus", modulus - 1, F4, false),
			("negative modulus", -modulus, F4, false),
			("negative exponent", modulus, -F4, false)
		];

		using (Assert.Multiple())
		{
			foreach ((string name, BigInteger value, BigInteger exponent, bool expected) in cases)
			{
				foreach (byte[] algorithm in (byte[][])[RsaEncryption, RsassaPss, RsassaPssIdentifier(), Sequence(Oid("1.2.840.113549.1.1.1")), Sequence(Oid(RsassaPssOid), [0x05, 0x00])])
				{
					SubjectPublicKeyInfo info = SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(value, exponent, algorithm));
					await Assert.That(CertificateAlgorithmPolicy.IsWithinVerificationBounds(info)).IsEqualTo(expected).Because($"{name}, {Convert.ToHexString(algorithm)}");
				}
			}
		}
	}

	[Test]
	public async Task RefusesRsaKeysThatDoNotDecode()
	{
		byte[] modulus = Integer(Modulus(2048));
		byte[] exponent = Integer(F4);

		(string Name, byte[] RsaPublicKey)[] cases =
		[
			("not a SEQUENCE", [0x05, 0x00]),
			("one INTEGER", Sequence(modulus)),
			("a third INTEGER", Sequence(modulus, exponent, exponent)),
			("a trailing byte", [.. Sequence(modulus, exponent), 0x00]),
			("long-form length", WithRedundantLengthByte(Sequence(modulus, exponent))),
			("redundant leading zero", Sequence(modulus, [0x02, 0x04, 0x00, 0x01, 0x00, 0x01]))
		];

		using (Assert.Multiple())
		{
			foreach ((string name, byte[] rsaPublicKey) in cases)
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.Decode(Sequence(RsaEncryption, Tlv(0x03, [0x00], rsaPublicKey)));
				await Assert.That(CertificateAlgorithmPolicy.IsWithinVerificationBounds(info)).IsFalse().Because(name);
				await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(info)).IsFalse().Because(name);
			}
		}
	}

	// Other keys take work that their algorithms bound, even those that the policy refuses in a path.
	[Test]
	public async Task DoesNotBoundOtherKeys()
	{
		using EcdsaP256 p256 = EcdsaP256.GenerateKey();
		using Ed25519 ed25519 = Ed25519.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That(CertificateAlgorithmPolicy.IsWithinVerificationBounds(SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(p256)))).IsTrue();
			await Assert.That(CertificateAlgorithmPolicy.IsWithinVerificationBounds(SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(ed25519)))).IsTrue();
			await Assert.That(CertificateAlgorithmPolicy.IsWithinVerificationBounds(SubjectPublicKeyInfo.Decode(Dsa()))).IsTrue();
			await Assert.That(CertificateAlgorithmPolicy.IsWithinVerificationBounds(SubjectPublicKeyInfo.Decode(Sequence(Sequence(Oid("1.2.3.4")), Tlv(0x03, [0x00]))))).IsTrue();
			await Assert.That(() => CertificateAlgorithmPolicy.IsWithinVerificationBounds(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// RSA moduli of minRsaKeySize to 16384 bits in whole bytes (CA/Browser Forum Baseline Requirements, Sec. 6.1.5), and the bounds of IsWithinVerificationBounds.
	[Test]
	[Arguments(2048, 2048, true)]
	[Arguments(2040, 2048, false)]
	[Arguments(2056, 2048, true)]
	[Arguments(2052, 2048, false)]
	[Arguments(2047, 1024, false)]
	[Arguments(2049, 1024, false)]
	[Arguments(1024, 1024, true)]
	[Arguments(2048, 3072, false)]
	[Arguments(3072, 3072, true)]
	[Arguments(16384, 16384, true)]
	[Arguments(16384, 2048, true)]
	[Arguments(16392, 2048, false)]
	public async Task AppliesThePolicyToRsaKeys(int bits, int minRsaKeySize, bool expected)
	{
		using (Assert.Multiple())
		{
			foreach (byte[] algorithm in (byte[][])[RsaEncryption, RsassaPss, Sequence(Oid("1.2.840.113549.1.1.1"))])
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(Modulus(bits), F4, algorithm));
				await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(info, minRsaKeySize)).IsEqualTo(expected).Because(Convert.ToHexString(algorithm));
			}
		}
	}

	[Test]
	public async Task AppliesThePolicyToInvalidRsaKeys()
	{
		BigInteger modulus = Modulus(2048);

		using (Assert.Multiple())
		{
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(modulus, F4)))).IsTrue();
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(modulus, (BigInteger.One << 33) + 1)))).IsFalse();
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(modulus - 1, F4)))).IsFalse();
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(modulus, 1)))).IsFalse();
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(-modulus, F4)))).IsFalse();
		}
	}

	// EC keys on the named curves P-256, P-384, P-521 and that of SM2 alone; DSA keys are refused, and other keys left to the importer.
	[Test]
	public async Task AppliesThePolicyToOtherKeys()
	{
		using EcdsaP256 p256 = EcdsaP256.GenerateKey();
		using EcdsaP384 p384 = EcdsaP384.GenerateKey();
		using EcdsaP521 p521 = EcdsaP521.GenerateKey();
		using Ed25519 ed25519 = Ed25519.GenerateKey();
		byte[] point = SubjectPublicKeyInfo.Decode(ExportSubjectPublicKeyInfo(p256)).PublicKey.ToArray();

		(string Name, byte[] SubjectPublicKeyInfo, bool Expected)[] cases =
		[
			("P-256", ExportSubjectPublicKeyInfo(p256), true),
			("P-384", ExportSubjectPublicKeyInfo(p384), true),
			("P-521", ExportSubjectPublicKeyInfo(p521), true),
			("SM2", ReadCertificate("sm2-leaf.pem").PublicKeyInfo.Encoded.ToArray(), true),
			("secp256k1", Sequence(Sequence(Oid(ECPublicKeyOid), Oid("1.3.132.0.10")), Tlv(0x03, [0x00], point)), false),
			("explicit curve", Sequence(Sequence(Oid(ECPublicKeyOid), Sequence([0x02, 0x01, 0x01])), Tlv(0x03, [0x00], point)), false),
			("id-ecPublicKey without parameters", Sequence(Sequence(Oid(ECPublicKeyOid)), Tlv(0x03, [0x00], point)), false),
			("DSA", Dsa(), false),
			("Ed25519", ExportSubjectPublicKeyInfo(ed25519), true),
			("ML-DSA-44", ReadCertificate("rfc9881-mldsa44.pem").PublicKeyInfo.Encoded.ToArray(), true),
			("X448", Sequence(Sequence(Oid("1.3.101.111")), Tlv(0x03, [0x00, .. new byte[56]])), true)
		];

		using (Assert.Multiple())
		{
			foreach ((string name, byte[] subjectPublicKeyInfo, bool expected) in cases)
			{
				await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(SubjectPublicKeyInfo.Decode(subjectPublicKeyInfo))).IsEqualTo(expected).Because(name);
			}
		}
	}

	// The rule of TrustAnchorCertificateValidator.MinRsaKeySize: 1024 to 16384.
	[Test]
	public async Task IsAcceptableInPathChecksItsArguments()
	{
		SubjectPublicKeyInfo info = SubjectPublicKeyInfo.Decode(RsaSubjectPublicKeyInfo(Modulus(2048), F4));

		using (Assert.Multiple())
		{
			await Assert.That(() => CertificateAlgorithmPolicy.IsAcceptableInPath(info, 1023)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("minRsaKeySize");
			await Assert.That(() => CertificateAlgorithmPolicy.IsAcceptableInPath(info, 16385)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("minRsaKeySize");
			await Assert.That(() => CertificateAlgorithmPolicy.IsAcceptableInPath(info, 0)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("minRsaKeySize");
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(info, 1024)).IsTrue();
			await Assert.That(CertificateAlgorithmPolicy.IsAcceptableInPath(info, 16384)).IsFalse();
			await Assert.That(() => CertificateAlgorithmPolicy.IsAcceptableInPath(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// An AlgorithmIdentifier from its DER, by way of a SubjectPublicKeyInfo without a key.
	private static AlgorithmIdentifier Identifier(byte[] encoded)
	{
		return SubjectPublicKeyInfo.Decode(Sequence(encoded, Tlv(0x03, [0x00]))).Algorithm;
	}

	private static byte[] Dsa()
	{
		return Sequence(Sequence(Oid("1.2.840.10040.4.1"), Sequence([0x02, 0x01, 0x03], [0x02, 0x01, 0x05], [0x02, 0x01, 0x07])), Tlv(0x03, [0x00, 0x02, 0x01, 0x09]));
	}

	// A deterministic odd modulus of bits bits; not a product of two primes, which the policy does not check.
	private static BigInteger Modulus(int bits)
	{
		return BigInteger.One << bits - 1 | new BigInteger(CreateDeterministicSource((bits - 1) / 8), isUnsigned: true, isBigEndian: true) | 1;
	}

	private static byte[] Integer(BigInteger value)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteInteger(value);
		return writer.Encode();
	}

	private static byte[] RsaSubjectPublicKeyInfo(BigInteger modulus, BigInteger exponent, byte[]? algorithm = null)
	{
		return Sequence(algorithm ?? RsaEncryption, Tlv(0x03, [0x00], Sequence(Integer(modulus), Integer(exponent))));
	}

	private static Certificate ReadCertificate(string file)
	{
		using Stream stream = typeof(CertificateAlgorithmPolicyTest).Assembly.GetManifestResourceStream(file) ?? throw new FileNotFoundException($"The certificate '{file}' is not embedded.", file);
		using StreamReader reader = new(stream);
		return Certificate.DecodePem(reader.ReadToEnd());
	}
}
