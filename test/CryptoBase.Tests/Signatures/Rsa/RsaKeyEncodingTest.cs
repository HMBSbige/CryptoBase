using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Rsa;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.Rsa.RsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa;

internal class RsaKeyEncodingTest
{
	private static readonly byte[] Null = [0x05, 0x00];

	[Test]
	[Arguments(512)]
	[Arguments(2048)]
	[Arguments(3072)]
	[Arguments(4096)]
	public async Task KeyFormatsRoundTrip(int bits)
	{
		RSAParameters parameters = PrivateParameters(bits);
		byte[] rsaPrivateKey = RsaPrivateKey(parameters);
		byte[] rsaPublicKey = RsaPublicKey(Os2Ip(parameters.Modulus), Os2Ip(parameters.Exponent));
		byte[] pkcs8 = Pkcs8PrivateKey(bits);
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(RsaEncryption, rsaPublicKey);

		using RsaKey fromPkcs8 = RsaKey.ImportPkcs8PrivateKey(pkcs8);
		using RsaKey fromRsaPrivateKey = RsaKey.ImportRsaPrivateKey(rsaPrivateKey);
		using RsaKey fromSubjectPublicKeyInfo = RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using RsaKey fromRsaPublicKey = RsaKey.ImportRsaPublicKey(rsaPublicKey);

		using (Assert.Multiple())
		{
			await Assert.That(pkcs8).IsEquivalentTo(PrivateKeyInfo(RsaEncryption, rsaPrivateKey), CollectionOrdering.Matching);

			foreach (RsaKey key in (RsaKey[])[fromPkcs8, fromRsaPrivateKey])
			{
				await Assert.That(key.HasPrivateKey).IsTrue();
				await Assert.That((key.RsaPrivateKeyLength, key.Pkcs8PrivateKeyLength)).IsEqualTo((rsaPrivateKey.Length, pkcs8.Length));
				await Assert.That(ExportRsaPrivateKey(key)).IsEquivalentTo(rsaPrivateKey, CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching);
			}

			foreach (RsaKey key in (RsaKey[])[fromPkcs8, fromRsaPrivateKey, fromSubjectPublicKeyInfo, fromRsaPublicKey])
			{
				await Assert.That(key.ModulusBits).IsEqualTo(bits);
				await Assert.That((key.RsaPublicKeyLength, key.SubjectPublicKeyInfoLength)).IsEqualTo((rsaPublicKey.Length, subjectPublicKeyInfo.Length));
				await Assert.That(ExportRsaPublicKey(key)).IsEquivalentTo(rsaPublicKey, CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			}

			foreach (RsaKey key in (RsaKey[])[fromSubjectPublicKeyInfo, fromRsaPublicKey])
			{
				byte[] destination = CreateGuardedBuffer(0, rsaPrivateKey.Length);
				await Assert.That(key.HasPrivateKey).IsFalse();
				await Assert.That(() => key.RsaPrivateKeyLength).ThrowsExactly<InvalidOperationException>();
				await Assert.That(() => key.ExportRsaPrivateKey(destination)).ThrowsExactly<InvalidOperationException>();
				await Assert.That(destination).All(static value => value is DestinationSentinel);
			}
		}
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task Pkcs1ExportsStayWithinTheirLength()
	{
		using RsaKey key = ImportKey();
		byte[] rsaPublicKey = ExportRsaPublicKey(key);
		byte[] rsaPrivateKey = ExportRsaPrivateKey(key);

		using (Assert.Multiple())
		{
			foreach (int shortfall in (int[])[1, int.MaxValue])
			{
				byte[] shortPublicKey = ShortBuffer(rsaPublicKey.Length, shortfall);
				byte[] shortPrivateKey = ShortBuffer(rsaPrivateKey.Length, shortfall);
				await Assert.That(() => key.ExportRsaPublicKey(shortPublicKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportRsaPrivateKey(shortPrivateKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(shortPublicKey).All(static value => value is DestinationSentinel);
				await Assert.That(shortPrivateKey).All(static value => value is DestinationSentinel);
			}

			byte[] publicKeyOutput = CreateGuardedBuffer(1, rsaPublicKey.Length);
			byte[] privateKeyOutput = CreateGuardedBuffer(1, rsaPrivateKey.Length);
			await Assert.That(key.ExportRsaPublicKey(publicKeyOutput.AsSpan(1))).IsEqualTo(rsaPublicKey.Length);
			await Assert.That(key.ExportRsaPrivateKey(privateKeyOutput.AsSpan(1))).IsEqualTo(rsaPrivateKey.Length);
			await AssertOutput(publicKeyOutput, 1, rsaPublicKey);
			await AssertOutput(privateKeyOutput, 1, rsaPrivateKey);
		}
	}

	// The bounds of the public key: moduli of 512 and 16384 bits, and exponents from 3 to 2^33 − 1; the modulus INTEGER has a zero byte before a top bit, which the export keeps.
	[Test]
	[Arguments(512, 3L)]
	[Arguments(16384, 65537L)]
	[Arguments(2047, 8589934591L)]
	[Arguments(2048, 4294967297L)]
	public async Task ImportsKeysAtTheBounds(int bits, long exponent)
	{
		byte[] rsaPublicKey = RsaPublicKey(Modulus(bits), exponent);
		using RsaKey key = RsaKey.ImportRsaPublicKey(rsaPublicKey);

		using (Assert.Multiple())
		{
			await Assert.That(key.ModulusBits).IsEqualTo(bits);
			await Assert.That(ExportRsaPublicKey(key)).IsEquivalentTo(rsaPublicKey, CollectionOrdering.Matching);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] RsaPublicKey)>> UnsupportedRsaPublicKeys()
	{
		yield return static () => ("modulus of 511 bits", RsaPublicKey(Modulus(511), 65537));
		yield return static () => ("modulus of 16385 bits", RsaPublicKey(Modulus(16385), 65537));
		yield return static () => ("modulus of 65536 bits", RsaPublicKey(Modulus(65536), 65537));
		yield return static () => ("exponent of 34 bits", RsaPublicKey(Modulus(2048), (BigInteger.One << 33) + 1));
		yield return static () => ("exponent of 64 bits", RsaPublicKey(Modulus(2048), ulong.MaxValue));
	}

	[Test]
	[MethodDataSource(nameof(UnsupportedRsaPublicKeys))]
	public async Task OutOfBoundsKeysAreNotSupported(string @case, byte[] rsaPublicKey)
	{
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(RsaEncryption, rsaPublicKey);

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportRsaPublicKey(rsaPublicKey)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("RSA PUBLIC KEY", rsaPublicKey))).ThrowsExactly<NotSupportedException>().Because(@case);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] RsaPublicKey)>> InvalidRsaPublicKeys()
	{
		BigInteger n = Modulus(2048);
		byte[] valid = RsaPublicKey(n, 65537);

		yield return static () => ("empty", []);
		yield return () => ("trailing byte", [.. valid, 0x00]);
		yield return () => ("truncated", valid.AsSpan(0, valid.Length - 1).ToArray());
		yield return () => ("long-form length", WithRedundantLengthByte(valid));
		yield return () => ("indefinite length", [0x30, 0x80, .. Contents(valid), 0x00, 0x00]);
		yield return () => ("SET", [0x31, .. valid.AsSpan(1)]);
		yield return () => ("modulus with a redundant zero byte", Sequence(Tlv(0x02, [0x00, .. Contents(Integer(n))]), Integer(65537)));
		yield return () => ("exponent with a redundant zero byte", Sequence(Integer(n), Tlv(0x02, [0x00, 0x01, 0x00, 0x01])));
		yield return () => ("empty exponent", Sequence(Integer(n), [0x02, 0x00]));
		yield return () => ("exponent as OCTET STRING", Sequence(Integer(n), Tlv(0x04, [0x01, 0x00, 0x01])));
		yield return () => ("negative modulus", Sequence(Integer(-n), Integer(65537)));
		yield return () => ("negative exponent", Sequence(Integer(n), Integer(-65537)));
		yield return () => ("zero modulus", RsaPublicKey(0, 65537));
		yield return () => ("even modulus", RsaPublicKey(n - 1, 65537));
		yield return () => ("zero exponent", RsaPublicKey(n, 0));
		yield return () => ("exponent 1", RsaPublicKey(n, 1));
		yield return () => ("even exponent", RsaPublicKey(n, 65536));
		yield return () => ("no exponent", Sequence(Integer(n)));
		yield return () => ("a third INTEGER", Sequence(Integer(n), Integer(65537), Integer(1)));
	}

	[Test]
	[MethodDataSource(nameof(InvalidRsaPublicKeys))]
	public async Task InvalidPublicKeysThrow(string @case, byte[] rsaPublicKey)
	{
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(RsaEncryption, rsaPublicKey);

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportRsaPublicKey(rsaPublicKey)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);

			if (rsaPublicKey.Length > 0)
			{
				await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("RSA PUBLIC KEY", rsaPublicKey))).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			}
		}
	}

	public static IEnumerable<Func<(string Case, byte[] RsaPrivateKey)>> InvalidRsaPrivateKeys()
	{
		RSAParameters parameters = PrivateParameters();
		(BigInteger n, BigInteger e, BigInteger d) = (Os2Ip(parameters.Modulus), Os2Ip(parameters.Exponent), Os2Ip(parameters.D));
		(BigInteger p, BigInteger q) = (Os2Ip(parameters.P), Os2Ip(parameters.Q));
		(BigInteger dP, BigInteger dQ, BigInteger qInv) = (Os2Ip(parameters.DP), Os2Ip(parameters.DQ), Os2Ip(parameters.InverseQ));
		BigInteger otherModulus = Os2Ip(ParsePkcs8(OtherKey2048).Modulus);
		byte[] valid = RsaPrivateKey(parameters);

		yield return static () => ("empty", []);
		yield return () => ("trailing byte", [.. valid, 0x00]);
		yield return () => ("truncated", valid.AsSpan(0, valid.Length - 1).ToArray());
		yield return () => ("long-form length", WithRedundantLengthByte(valid));
		yield return () => ("version 2", Key(2, n, e, d, p, q, dP, dQ, qInv));
		yield return () => ("version −1", Key(-1, n, e, d, p, q, dP, dQ, qInv));
		yield return () => ("version 0 with otherPrimeInfos", RsaPrivateKey(parameters, Sequence(Sequence(Integer(7), Integer(5), Integer(3)))));
		yield return () => ("no coefficient", Key(0, n, e, d, p, q, dP, dQ));
		yield return () => ("an INTEGER after the coefficient", Key(0, n, e, d, p, q, dP, dQ, qInv, 1));
		yield return () => ("negative private exponent", Key(0, n, e, -d, p, q, dP, dQ, qInv));
		yield return () => ("negative coefficient", Key(0, n, e, d, p, q, dP, dQ, qInv - p));
		yield return () => ("even modulus", Key(0, n - 1, e, d, p, q, dP, dQ, qInv));
		yield return () => ("modulus of another key", Key(0, otherModulus, e, d, p, q, dP, dQ, qInv));
		yield return () => ("primes swapped", Key(0, n, e, d, q, p, dQ, dP, qInv));
		yield return () => ("prime 1 = n and prime 2 = 1", Key(0, n, e, d, n, 1, dP, dQ, qInv));
		yield return () => ("private exponent 0", Key(0, n, e, 0, p, q, dP, dQ, qInv));
		yield return () => ("private exponent + 1", Key(0, n, e, d + 1, p, q, dP, dQ, qInv));
		yield return () => ("private exponent + φ(n), at least n", Key(0, n, e, d + (p - 1) * (q - 1), p, q, dP, dQ, qInv));
		yield return () => ("exponent 1 + 1", Key(0, n, e, d, p, q, dP + 1, dQ, qInv));
		yield return () => ("exponent 1 + p − 1", Key(0, n, e, d, p, q, dP + p - 1, dQ, qInv));
		yield return () => ("exponent 2 = 0", Key(0, n, e, d, p, q, dP, 0, qInv));
		yield return () => ("exponent 2 + q − 1", Key(0, n, e, d, p, q, dP, dQ + q - 1, qInv));
		yield return () => ("coefficient + 1", Key(0, n, e, d, p, q, dP, dQ, qInv + 1));
		yield return () => ("coefficient + p", Key(0, n, e, d, p, q, dP, dQ, qInv + p));
		yield return () => ("coefficient 0", Key(0, n, e, d, p, q, dP, dQ, 0));
		yield return () => ("public exponent + 2", Key(0, n, e + 2, d, p, q, dP, dQ, qInv));
	}

	// The import rejects each key with ArgumentException and leaves the caller's buffer unchanged.
	[Test]
	[MethodDataSource(nameof(InvalidRsaPrivateKeys))]
	public async Task InvalidPrivateKeysThrow(string @case, byte[] rsaPrivateKey)
	{
		byte[] pkcs8 = PrivateKeyInfo(RsaEncryption, rsaPrivateKey);
		byte[] copy = rsaPrivateKey.ToArray();

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportRsaPrivateKey(rsaPrivateKey)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => RsaKey.ImportPkcs8PrivateKey(pkcs8)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(pkcs8)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(rsaPrivateKey).IsEquivalentTo(copy, CollectionOrdering.Matching);

			if (rsaPrivateKey.Length > 0)
			{
				await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("RSA PRIVATE KEY", rsaPrivateKey))).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			}
		}
	}

	// Version 1 means otherPrimeInfos (RFC 8017, Appendix A.1.2), which the version alone rules out, so the values here need not be consistent.
	[Test]
	public async Task MultiPrimeKeysAreNotSupported()
	{
		RSAParameters parameters = PrivateParameters();
		byte[][] values = [parameters.Modulus!, parameters.Exponent!, parameters.D!, parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ!];
		byte[] otherPrimeInfos = Sequence(Sequence(Integer(7), Integer(5), Integer(3)));
		byte[] rsaPrivateKey = Sequence([Integer(1), .. values.Select(static value => Integer(Os2Ip(value))), otherPrimeInfos]);
		byte[] pkcs8 = PrivateKeyInfo(RsaEncryption, rsaPrivateKey);

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportRsaPrivateKey(rsaPrivateKey)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => RsaKey.ImportPkcs8PrivateKey(pkcs8)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(pkcs8)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("RSA PRIVATE KEY", rsaPrivateKey))).ThrowsExactly<NotSupportedException>();
		}
	}

	// A PKCS #8 import accepts attributes and a matching public key (RFC 5958), and the export holds the RSAPrivateKey alone.
	[Test]
	public async Task Pkcs8ImportAcceptsAttributesAndTheMatchingPublicKey()
	{
		using RsaKey key = ImportKey();
		byte[] rsaPrivateKey = ExportRsaPrivateKey(key);
		byte[] rsaPublicKey = ExportRsaPublicKey(key);
		byte[] attributes = Tlv(0xA0, Sequence(Oid("1.2.840.113549.1.9.20"), Tlv(0x31, Tlv(0x1E, [0x00, 0x41]))));
		byte[][] encodings =
		[
			PrivateKeyInfo(RsaEncryption, rsaPrivateKey, attributes),
			Sequence(Integer(1), RsaEncryption, Tlv(0x04, rsaPrivateKey), Tlv(0x81, [0x00, .. rsaPublicKey])),
			Sequence(Integer(1), RsaEncryption, Tlv(0x04, rsaPrivateKey), attributes, Tlv(0x81, [0x00, .. rsaPublicKey])),
		];

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in encodings)
			{
				using RsaKey imported = RsaKey.ImportPkcs8PrivateKey(encoding);
				await Assert.That(ExportPkcs8PrivateKey(imported)).IsEquivalentTo(Pkcs8PrivateKey(), CollectionOrdering.Matching).Because(Convert.ToHexString(encoding.AsSpan(0, 8)));
			}
		}
	}

	public static IEnumerable<Func<(string Case, byte[] PrivateKeyInfo)>> InvalidPrivateKeyInfos()
	{
		RSAParameters parameters = PrivateParameters();
		byte[] rsaPrivateKey = RsaPrivateKey(parameters);
		byte[] rsaPublicKey = RsaPublicKey(Os2Ip(parameters.Modulus), Os2Ip(parameters.Exponent));
		byte[] otherPublicKey = RsaPublicKey(Os2Ip(ParsePkcs8(OtherKey2048).Modulus), 65537);

		yield return () => ("version 2", Sequence(Integer(2), RsaEncryption, Tlv(0x04, rsaPrivateKey)));
		yield return () => ("rsaEncryption without parameters", PrivateKeyInfo(Sequence(Oid(RsaEncryptionOid)), rsaPrivateKey));
		yield return () => ("rsaEncryption with an OCTET STRING", PrivateKeyInfo(Sequence(Oid(RsaEncryptionOid), Tlv(0x04)), rsaPrivateKey));
		yield return () => ("rsaEncryption with two NULLs", PrivateKeyInfo(Sequence(Oid(RsaEncryptionOid), Null, Null), rsaPrivateKey));
		yield return () => ("id-ecPublicKey", PrivateKeyInfo(Sequence(Oid("1.2.840.10045.2.1"), Oid("1.2.840.10045.3.1.7")), rsaPrivateKey));
		yield return () => ("an RSAPublicKey", PrivateKeyInfo(RsaEncryption, rsaPublicKey));
		yield return () => ("an RSAPrivateKey in a BIT STRING", Sequence(Integer(0), RsaEncryption, Tlv(0x03, [0x00, .. rsaPrivateKey])));
		yield return () => ("a byte after the RSAPrivateKey", PrivateKeyInfo(RsaEncryption, [.. rsaPrivateKey, 0x00]));
		yield return () => ("a public key of another key", Sequence(Integer(1), RsaEncryption, Tlv(0x04, rsaPrivateKey), Tlv(0x81, [0x00, .. otherPublicKey])));
		yield return () => ("a public key with a byte after it", Sequence(Integer(1), RsaEncryption, Tlv(0x04, rsaPrivateKey), Tlv(0x81, [0x00, .. rsaPublicKey, 0x00])));
		yield return () => ("a public key in version 0", Sequence(Integer(0), RsaEncryption, Tlv(0x04, rsaPrivateKey), Tlv(0x81, [0x00, .. rsaPublicKey])));
		yield return () => ("an empty public key", Sequence(Integer(1), RsaEncryption, Tlv(0x04, rsaPrivateKey), Tlv(0x81, [0x00])));
		yield return () => ("a SubjectPublicKeyInfo", SubjectPublicKeyInfo(RsaEncryption, rsaPublicKey));
	}

	[Test]
	[MethodDataSource(nameof(InvalidPrivateKeyInfos))]
	public async Task InvalidPrivateKeyInfosThrow(string @case, byte[] privateKeyInfo)
	{
		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportPkcs8PrivateKey(privateKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => RsaKey.ImportPkcs8PrivateKey([.. privateKeyInfo, 0x00])).Throws<ArgumentException>().WithParameterName("source").Because(@case);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] SubjectPublicKeyInfo)>> InvalidSubjectPublicKeyInfos()
	{
		RSAParameters parameters = PrivateParameters();
		byte[] rsaPublicKey = RsaPublicKey(Os2Ip(parameters.Modulus), Os2Ip(parameters.Exponent));

		yield return () => ("unused bits", Sequence(RsaEncryption, Tlv(0x03, [0x01, .. rsaPublicKey])));
		yield return () => ("constructed BIT STRING", Sequence(RsaEncryption, Tlv(0x23, Tlv(0x03, [0x00, .. rsaPublicKey]))));
		yield return () => ("a byte after the RSAPublicKey", SubjectPublicKeyInfo(RsaEncryption, [.. rsaPublicKey, 0x00]));
		yield return () => ("rsaEncryption without parameters", SubjectPublicKeyInfo(Sequence(Oid(RsaEncryptionOid)), rsaPublicKey));
		yield return () => ("rsaEncryption with a long-form length", SubjectPublicKeyInfo(WithRedundantLengthByte(RsaEncryption), rsaPublicKey));
		yield return () => ("an RSAPrivateKey", SubjectPublicKeyInfo(RsaEncryption, RsaPrivateKey(parameters)));
		yield return () => ("a byte after the SubjectPublicKeyInfo", [.. SubjectPublicKeyInfo(RsaEncryption, rsaPublicKey), 0x00]);
		yield return () => ("an AlgorithmIdentifier alone", RsaEncryption);
		yield return () => ("a PrivateKeyInfo", Pkcs8PrivateKey());
	}

	[Test]
	[MethodDataSource(nameof(InvalidSubjectPublicKeyInfos))]
	public async Task InvalidSubjectPublicKeyInfosThrow(string @case, byte[] subjectPublicKeyInfo)
	{
		await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
	}

	public static IEnumerable<Func<(string Case, byte[] AlgorithmIdentifier, SignatureAlgorithm[] Allowed)>> SupportedPssParameters()
	{
		yield return static () => ("no parameters", RsassaPssIdentifier(withParameters: false), PssAlgorithms);
		yield return static () => ("SHA-256", RsassaPssIdentifier(), [SignatureAlgorithm.RsaPssSha256]);
		yield return static () => ("SHA-384", RsassaPssIdentifier(hash: Sha384Oid, maskHash: Sha384Oid, saltLength: 48), [SignatureAlgorithm.RsaPssSha384]);
		yield return static () => ("SHA-512", RsassaPssIdentifier(hash: Sha512Oid, maskHash: Sha512Oid, saltLength: 64), [SignatureAlgorithm.RsaPssSha512]);
		yield return static () => ("SHA-512 with a saltLength of 32", RsassaPssIdentifier(hash: Sha512Oid, maskHash: Sha512Oid, saltLength: 32), [SignatureAlgorithm.RsaPssSha512]);
		yield return static () => ("default saltLength of 20", RsassaPssIdentifier(saltLength: null), [SignatureAlgorithm.RsaPssSha256]);
		yield return static () => ("saltLength 0", RsassaPssIdentifier(saltLength: 0), [SignatureAlgorithm.RsaPssSha256]);
		yield return static () => ("absent hash parameters", RsassaPssIdentifier(nullParameters: false, maskNullParameters: false), [SignatureAlgorithm.RsaPssSha256]);
		yield return static () => ("absent parameters of the MGF1 hash alone", RsassaPssIdentifier(maskNullParameters: false), [SignatureAlgorithm.RsaPssSha256]);
		yield return static () => ("explicit trailer field", RsassaPssIdentifier(trailerField: 1), [SignatureAlgorithm.RsaPssSha256]);
	}

	// RFC 4055, Sec. 3.3: the parameters restrict the key to the algorithms that they allow, and the encodings keep them.
	[Test]
	[MethodDataSource(nameof(SupportedPssParameters))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task PssParametersRestrictTheAlgorithms(string @case, byte[] algorithmIdentifier, SignatureAlgorithm[] allowed)
	{
		using RsaKey unrestricted = ImportKey();
		using RSA bcl = CreateBclKey();
		byte[] rsaPublicKey = ExportRsaPublicKey(unrestricted);
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, rsaPublicKey);
		byte[] pkcs8 = PrivateKeyInfo(algorithmIdentifier, ExportRsaPrivateKey(unrestricted));
		using RsaKey publicKey = RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using RsaKey privateKey = RsaKey.ImportPkcs8PrivateKey(pkcs8);
		using ISignatureKey dispatchedPublicKey = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using ISignatureKey dispatchedPrivateKey = SignatureKey.ImportFromPem(PemEncoding.WriteString("PRIVATE KEY", pkcs8));
		byte[] message = CreateDeterministicSource(30);

		using (Assert.Multiple())
		{
			foreach (ISignatureKey key in (ISignatureKey[])[publicKey, privateKey, dispatchedPublicKey, dispatchedPrivateKey])
			{
				await Assert.That(key.GetType()).IsEqualTo(typeof(RsaKey)).Because(@case);
				await Assert.That(Algorithms.Where(key.Supports)).IsEquivalentTo(allowed, CollectionOrdering.Matching).Because(@case);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching).Because(@case);
			}

			await Assert.That(ExportPkcs8PrivateKey(privateKey)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching).Because(@case);
			await Assert.That(ExportRsaPublicKey(privateKey)).IsEquivalentTo(rsaPublicKey, CollectionOrdering.Matching).Because(@case);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				byte[] signature = Sign(unrestricted, algorithm, message);

				if (allowed.Contains(algorithm))
				{
					(HashAlgorithmName hash, RSASignaturePadding padding, _) = ParametersOf(algorithm);
					byte[] restrictedSignature = Sign(privateKey, algorithm, message);
					await Assert.That(publicKey.Verify(algorithm, message, signature)).IsTrue().Because($"{@case}, {algorithm}");
					await Assert.That(publicKey.Verify(algorithm, message, restrictedSignature)).IsTrue().Because($"{@case}, {algorithm}");
					await Assert.That(bcl.VerifyData(message, restrictedSignature, hash, padding)).IsTrue().Because($"{@case}, {algorithm}");
					continue;
				}

				byte[] destination = CreateGuardedBuffer(0, signature.Length);
				await Assert.That(() => privateKey.Sign(algorithm, message, destination)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => publicKey.Verify(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => publicKey.GetMaxSignatureLength(algorithm)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(destination).All(static value => value is DestinationSentinel);
			}
		}
	}

	public static IEnumerable<Func<(string Case, byte[] AlgorithmIdentifier)>> UnsupportedPssParameters()
	{
		yield return static () => ("saltLength longer than the hash", RsassaPssIdentifier(saltLength: 33));
		yield return static () => ("default hash, SHA-1", RsassaPssIdentifier(hash: null));
		yield return static () => ("default mask generation function, MGF1 with SHA-1", RsassaPssIdentifier(maskHash: null));
		yield return static () => ("every field default", PssIdentifier());
		yield return static () => ("MGF1 with another hash", RsassaPssIdentifier(hash: Sha512Oid, saltLength: 64));
		yield return static () => ("SHA-1", RsassaPssIdentifier(hash: "1.3.14.3.2.26", maskHash: "1.3.14.3.2.26", saltLength: 20));
		yield return static () => ("SHA-224", RsassaPssIdentifier(hash: "2.16.840.1.101.3.4.2.4", maskHash: "2.16.840.1.101.3.4.2.4", saltLength: 28));
		yield return static () => ("SHA3-256", RsassaPssIdentifier(hash: "2.16.840.1.101.3.4.2.8", maskHash: "2.16.840.1.101.3.4.2.8", saltLength: 32));
		yield return static () => ("another mask generation function", RsassaPssIdentifier(maskGenerationFunction: "1.2.840.113549.1.1.99"));
		yield return static () => ("trailer field 2", RsassaPssIdentifier(trailerField: 2));
		yield return static () => ("negative saltLength", RsassaPssIdentifier(saltLength: -1));
		yield return static () => ("hash with OCTET STRING parameters", PssIdentifier(Tlv(0xA0, Sequence(Oid(Sha256Oid), Tlv(0x04))), Mgf1Field(Sha256Oid), Tlv(0xA2, Integer(32))));
		yield return static () => ("MGF1 hash with OCTET STRING parameters", PssIdentifier(HashField(Sha256Oid), Tlv(0xA1, Sequence(Oid(Mgf1Oid), Sequence(Oid(Sha256Oid), Tlv(0x04)))), Tlv(0xA2, Integer(32))));
	}

	[Test]
	[MethodDataSource(nameof(UnsupportedPssParameters))]
	public async Task PssParametersThatAllowNoAlgorithmAreNotSupported(string @case, byte[] algorithmIdentifier)
	{
		using RsaKey key = ImportKey();
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, ExportRsaPublicKey(key));
		byte[] pkcs8 = PrivateKeyInfo(algorithmIdentifier, ExportRsaPrivateKey(key));

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => RsaKey.ImportPkcs8PrivateKey(pkcs8)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(pkcs8)).ThrowsExactly<NotSupportedException>().Because(@case);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] AlgorithmIdentifier)>> MalformedPssParameters()
	{
		byte[] hash = HashField(Sha256Oid);
		byte[] mask = Mgf1Field(Sha256Oid);
		byte[] salt = Tlv(0xA2, Integer(32));
		byte[] parameters = Sequence(hash, mask, salt);

		yield return static () => ("NULL parameters", Sequence(Oid(RsassaPssOid), Null));
		yield return () => ("two parameters", Sequence(Oid(RsassaPssOid), parameters, Null));
		yield return () => ("fields out of order", PssIdentifier(mask, hash, salt));
		yield return () => ("a field [4]", PssIdentifier(hash, mask, salt, Tlv(0xA4, Integer(1))));
		yield return () => ("a field repeated", PssIdentifier(hash, hash, mask, salt));
		yield return () => ("saltLength as OCTET STRING", PssIdentifier(hash, mask, Tlv(0xA2, Tlv(0x04, [0x20]))));
		yield return () => ("saltLength beyond 32 bits", PssIdentifier(hash, mask, Tlv(0xA2, Integer(1L << 40))));
		yield return () => ("saltLength with a redundant zero byte", PssIdentifier(hash, mask, Tlv(0xA2, [0x02, 0x02, 0x00, 0x20])));
		yield return () => ("saltLength with two INTEGERs", PssIdentifier(hash, mask, Tlv(0xA2, Integer(32), Integer(32))));
		yield return () => ("trailerField as BOOLEAN", PssIdentifier(hash, mask, salt, Tlv(0xA3, [0x01, 0x01, 0xFF])));
		yield return () => ("hash field with two AlgorithmIdentifiers", PssIdentifier(Tlv(0xA0, Sequence(Oid(Sha256Oid)), Sequence(Oid(Sha256Oid))), mask, salt));
		yield return () => ("hash with two parameters", PssIdentifier(Tlv(0xA0, Sequence(Oid(Sha256Oid), Null, Null)), mask, salt));
		yield return () => ("hash as an OID alone", PssIdentifier(Tlv(0xA0, Oid(Sha256Oid)), mask, salt));
		yield return () => ("MGF1 without parameters", PssIdentifier(hash, Tlv(0xA1, Sequence(Oid(Mgf1Oid))), salt));
		yield return () => ("MGF1 with NULL parameters", PssIdentifier(hash, Tlv(0xA1, Sequence(Oid(Mgf1Oid), Null)), salt));
		yield return () => ("primitive field tags", PssIdentifier([0x80, .. hash.AsSpan(1)], mask, salt));
		yield return () => ("parameters with a long-form length", Sequence(Oid(RsassaPssOid), WithRedundantLengthByte(parameters)));
		yield return () => ("hash field with a long-form length", PssIdentifier(WithRedundantLengthByte(hash), mask, salt));
		yield return () => ("parameters with an indefinite length", Sequence(Oid(RsassaPssOid), [0x30, 0x80, .. Contents(parameters), 0x00, 0x00]));
	}

	[Test]
	[MethodDataSource(nameof(MalformedPssParameters))]
	public async Task MalformedPssParametersThrow(string @case, byte[] algorithmIdentifier)
	{
		using RsaKey key = ImportKey();
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, ExportRsaPublicKey(key));
		byte[] pkcs8 = PrivateKeyInfo(algorithmIdentifier, ExportRsaPrivateKey(key));

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => RsaKey.ImportPkcs8PrivateKey(pkcs8)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(pkcs8)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
		}
	}

	// RSAPrivateKey with the version and values given; a value of 0 is an INTEGER 0.
	private static byte[] Key(int version, params BigInteger[] values)
	{
		return Sequence([Integer(version), .. values.Select(Integer)]);
	}

	// id-RSASSA-PSS with RSASSA-PSS-params of the fields given.
	private static byte[] PssIdentifier(params byte[][] fields)
	{
		return Sequence(Oid(RsassaPssOid), Sequence(fields));
	}

	private static byte[] HashField(string hash)
	{
		return Tlv(0xA0, Sequence(Oid(hash), Null));
	}

	private static byte[] Mgf1Field(string hash)
	{
		return Tlv(0xA1, Sequence(Oid(Mgf1Oid), Sequence(Oid(hash), Null)));
	}
}
