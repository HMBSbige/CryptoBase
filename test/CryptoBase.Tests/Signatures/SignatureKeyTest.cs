using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.Signatures.Ecdsa;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
internal class SignatureKeyTest
{
	private const string P256Oid = "1.2.840.10045.3.1.7";

	public static IEnumerable<Func<KeyType>> KeyTypeCases()
	{
		return KeyTypes.Select(static type => (Func<KeyType>)(() => type));
	}

	[Test]
	[MethodDataSource(nameof(KeyTypeCases))]
	public async Task ImportsAsTheTypeOfTheAlgorithm(KeyType type)
	{
		using ISignatureKey generated = type.GenerateKey();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(generated);
		byte[] privateKey = ExportPkcs8PrivateKey(generated);

		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using ISignatureKey fromPrivateKey = SignatureKey.ImportPkcs8PrivateKey(privateKey);
		using ISignatureKey publicPem = SignatureKey.ImportFromPem(PemEncoding.WriteString("PUBLIC KEY", subjectPublicKeyInfo));
		using ISignatureKey privatePem = SignatureKey.ImportFromPem($"-----BEGIN CERTIFICATE-----\nnot base64\n{PemEncoding.WriteString("PRIVATE KEY", privateKey)}");
		SignatureAlgorithm algorithm = type.Algorithms[0];
		byte[] message = "message"u8.ToArray();
		byte[] signature = Sign(fromPrivateKey, algorithm, message);

		using (Assert.Multiple())
		{
			foreach (ISignatureKey key in (ISignatureKey[])[publicKey, fromPrivateKey, publicPem, privatePem])
			{
				await Assert.That(key.GetType()).IsEqualTo(type.Type);
				await Assert.That(key.Verify(algorithm, message, signature)).IsTrue();
			}

			await Assert.That(publicKey.HasPrivateKey).IsFalse();
			await Assert.That(publicPem.HasPrivateKey).IsFalse();
			await Assert.That(fromPrivateKey.HasPrivateKey).IsTrue();
			await Assert.That(privatePem.HasPrivateKey).IsTrue();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ImportsBclKeys([Matrix(256, 384, 521)] int curveBits)
	{
		(KeyType type, ECCurve curve) = EcdsaCurve(curveBits);
		using ECDsa key = ECDsa.Create(curve);

		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo());
		using ISignatureKey privateKey = SignatureKey.ImportPkcs8PrivateKey(key.ExportPkcs8PrivateKey());
		byte[] message = "message"u8.ToArray();
		byte[] signature = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

		using (Assert.Multiple())
		{
			await Assert.That(publicKey.GetType()).IsEqualTo(type.Type);
			await Assert.That(privateKey.GetType()).IsEqualTo(type.Type);
			await Assert.That(publicKey.Verify(SignatureAlgorithm.EcdsaSha256, message, signature)).IsTrue();
		}
	}

	public static IEnumerable<Func<(string Case, byte[] SubjectPublicKeyInfo)>> UnsupportedPublicKeys()
	{
		byte[] point = new byte[65];
		point[0] = 0x04;
		byte[] key = [0x03, 0x42, 0x00, .. point];

		yield return () => ("secp256k1", Sequence(EcdsaTestUtils.AlgorithmIdentifier("1.3.132.0.10"), key));
		yield return () => ("brainpoolP256r1", Sequence(EcdsaTestUtils.AlgorithmIdentifier("1.3.36.3.3.2.8.1.1.7"), key));
		yield return () => ("implicit curve", Sequence(Sequence(Oid("1.2.840.10045.2.1"), [0x05, 0x00]), key));
		yield return () => ("explicit curve", Sequence(Sequence(Oid("1.2.840.10045.2.1"), Sequence([0x02, 0x01, 0x01])), key));
		yield return () => ("no curve", Sequence(Sequence(Oid("1.2.840.10045.2.1")), key));
		yield return () => ("ML-DSA with parameters", Sequence(Sequence(Oid("2.16.840.1.101.3.4.3.17"), [0x05, 0x00]), [0x03, 0x01, 0x00]));
		yield return () => ("Ed25519", Sequence(Sequence(Oid("1.3.101.112")), [0x03, 0x21, 0x00, .. new byte[32]]));
		yield return () => ("RSA", RSA.Create(2048).ExportSubjectPublicKeyInfo());
	}

	[Test]
	[MethodDataSource(nameof(UnsupportedPublicKeys))]
	public async Task OtherAlgorithmsAreNotSupported(string @case, byte[] subjectPublicKeyInfo)
	{
		using (Assert.Multiple())
		{
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
			await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("PUBLIC KEY", subjectPublicKeyInfo))).ThrowsExactly<NotSupportedException>().Because(@case);
		}
	}

	[Test]
	public async Task OtherPrivateKeyAlgorithmsAreNotSupported()
	{
		using RSA rsa = RSA.Create(2048);
		byte[] secp256k1 = EcdsaTestUtils.Pkcs8("1.3.132.0.10", EcdsaTestUtils.ECPrivateKey(1, new byte[32], null, null));

		using (Assert.Multiple())
		{
			await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(rsa.ExportPkcs8PrivateKey())).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(secp256k1)).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task MalformedEncodingsThrow()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] privateKey = ExportPkcs8PrivateKey(key);
		byte[] notOnTheCurve = subjectPublicKeyInfo.ToArray();
		notOnTheCurve[^1] ^= 1;
		List<byte[]> publicKeys = [[], [.. subjectPublicKeyInfo, 0], subjectPublicKeyInfo.AsSpan(0, subjectPublicKeyInfo.Length - 1).ToArray(), [0x31, .. subjectPublicKeyInfo.AsSpan(1)], notOnTheCurve, Sequence(Sequence([0x05, 0x00]), [0x03, 0x01, 0x00]), Sequence(Sequence(Oid("1.2.840.10045.2.1"), [0x05, 0x00], [0x05, 0x00]), [0x03, 0x01, 0x00]), privateKey];
		List<byte[]> privateKeys = [[], [.. privateKey, 0], privateKey.AsSpan(0, privateKey.Length - 1).ToArray(), Sequence(EcdsaTestUtils.AlgorithmIdentifier(P256Oid)), subjectPublicKeyInfo];

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in publicKeys)
			{
				await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
			}

			foreach (byte[] encoding in privateKeys)
			{
				await Assert.That(() => SignatureKey.ImportPkcs8PrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
			}
		}
	}

	[Test]
	public async Task PemNeedsExactlyOneKey()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] privateKey = ExportPkcs8PrivateKey(key);
		string publicPem = PemEncoding.WriteString("PUBLIC KEY", subjectPublicKeyInfo);
		string privatePem = PemEncoding.WriteString("PRIVATE KEY", privateKey);
		string ecPrivatePem = PemEncoding.WriteString("EC PRIVATE KEY", EcdsaTestUtils.ECPrivateKey(1, EcdsaTestUtils.ExportPrivateKey(key), P256Oid, null));

		using (Assert.Multiple())
		{
			await Assert.That(() => SignatureKey.ImportFromPem("")).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("ENCRYPTED PRIVATE KEY", privateKey))).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => SignatureKey.ImportFromPem(publicPem + privatePem)).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => SignatureKey.ImportFromPem(publicPem + publicPem)).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => SignatureKey.ImportFromPem(ecPrivatePem + privatePem)).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("PRIVATE KEY", subjectPublicKeyInfo))).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	// The first text is as openssl ecparam -genkey writes a key, after an EC PARAMETERS block; the second holds only the fields that RFC 5915 requires.
	[Test]
	[MatrixDataSource]
	public async Task ImportsECPrivateKeyBlocks([Matrix(256, 384, 521)] int curveBits)
	{
		(KeyType type, ECCurve curve) = EcdsaCurve(curveBits);
		using ECDsa platform = ECDsa.Create(curve);
		string curveOid = await Assert.That(curve.Oid.Value).IsNotNull();
		byte[] d = platform.ExportParameters(includePrivateParameters: true).D ?? throw new InvalidOperationException("The exported parameters hold the private key.");
		string[] texts = [$"{PemEncoding.WriteString("EC PARAMETERS", Oid(curveOid))}\n{platform.ExportECPrivateKeyPem()}", PemEncoding.WriteString("EC PRIVATE KEY", EcdsaTestUtils.ECPrivateKey(1, d, curveOid, null))];
		byte[] message = "message"u8.ToArray();

		using (Assert.Multiple())
		{
			foreach (string text in texts)
			{
				using ISignatureKey key = SignatureKey.ImportFromPem(text);
				byte[] signature = Sign(key, SignatureAlgorithm.EcdsaSha256, message);
				await Assert.That(key.GetType()).IsEqualTo(type.Type);
				await Assert.That(key.HasPrivateKey).IsTrue();
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(platform.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
				await Assert.That(platform.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
			}
		}
	}

	public static IEnumerable<Func<(string Case, byte[] ECPrivateKey)>> UnsupportedECPrivateKeys()
	{
		byte[] d = new byte[32];
		d[^1] = 1;

		yield return () => ("secp256k1", EcdsaTestUtils.ECPrivateKey(1, d, "1.3.132.0.10", null));
		yield return () => ("brainpoolP256r1", EcdsaTestUtils.ECPrivateKey(1, d, "1.3.36.3.3.2.8.1.1.7", null));
		yield return () => ("implicit curve", EcdsaTestUtils.ECPrivateKey(1, d, null, null, EcdsaTestUtils.Element(0xA0, [0x05, 0x00])));
		yield return () => ("explicit curve", EcdsaTestUtils.ECPrivateKey(1, d, null, null, EcdsaTestUtils.Element(0xA0, Sequence([0x02, 0x01, 0x01]))));
	}

	[Test]
	[MethodDataSource(nameof(UnsupportedECPrivateKeys))]
	public async Task OtherCurvesOfECPrivateKeysAreNotSupported(string @case, byte[] ecPrivateKey)
	{
		await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("EC PRIVATE KEY", ecPrivateKey))).ThrowsExactly<NotSupportedException>().Because(@case);
	}

	[Test]
	public async Task MalformedECPrivateKeyBlocksThrow()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		using EcdsaP256 other = EcdsaP256.GenerateKey();
		byte[] d = EcdsaTestUtils.ExportPrivateKey(key);
		byte[] q = EcdsaTestUtils.ExportPublicKey(key);
		byte[] valid = EcdsaTestUtils.ECPrivateKey(1, d, P256Oid, q);
		// Malformed DER, a PrivateKeyInfo, parameters that are absent, empty or two values, and keys that the importer rejects.
		byte[][] encodings =
		[
			[], [.. valid, 0], valid.AsSpan(0, valid.Length - 1).ToArray(), ExportPkcs8PrivateKey(key),
			EcdsaTestUtils.ECPrivateKey(1, d, null, q), EcdsaTestUtils.ECPrivateKey(1, d, null, null), EcdsaTestUtils.ECPrivateKey(1, d, null, null, [0xA0, 0x00]),
			EcdsaTestUtils.ECPrivateKey(1, d, null, null, EcdsaTestUtils.Element(0xA0, [.. Oid(P256Oid), 0x05, 0x00])),
			EcdsaTestUtils.ECPrivateKey(0, d, P256Oid, q), EcdsaTestUtils.ECPrivateKey(1, d, P256Oid, EcdsaTestUtils.ExportPublicKey(other))
		];
		// The headers of RFC 1421 make the block not one of RFC 7468, whatever follows them.
		string encrypted = $"-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,F3C51F304AD3B1D4A1E3777FC27F3EC7\n\n{Convert.ToBase64String(valid)}\n-----END EC PRIVATE KEY-----\n";

		using ISignatureKey imported = SignatureKey.ImportFromPem(PemEncoding.WriteString("EC PRIVATE KEY", valid));

		using (Assert.Multiple())
		{
			await Assert.That(ExportSubjectPublicKeyInfo(imported)).IsEquivalentTo(ExportSubjectPublicKeyInfo(key), CollectionOrdering.Matching);

			foreach (byte[] encoding in encodings)
			{
				await Assert.That(() => SignatureKey.ImportFromPem(PemEncoding.WriteString("EC PRIVATE KEY", encoding))).Throws<ArgumentException>().WithParameterName("source").Because(Convert.ToHexString(encoding));
			}

			await Assert.That(() => SignatureKey.ImportFromPem(encrypted)).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ImportsExportablePrivateKeysOfCertificates([Matrix(256, 384, 521)] int curveBits)
	{
		(KeyType type, ECCurve curve) = EcdsaCurve(curveBits);
		using ECDsa platform = ECDsa.Create(curve);
		using X509Certificate2 certificate = LoadPkcs12(platform, exportable: true);

		await Assert.That(SignatureKey.TryImportPrivateKey(certificate, out ISignatureKey? imported)).IsTrue();
		using ISignatureKey key = await Assert.That(imported).IsNotNull();
		byte[] message = "message"u8.ToArray();
		byte[] signature = Sign(key, SignatureAlgorithm.EcdsaSha256, message);

		using (Assert.Multiple())
		{
			await Assert.That(key.GetType()).IsEqualTo(type.Type);
			await Assert.That(key.HasPrivateKey).IsTrue();
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(certificate.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
			await Assert.That(platform.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
		}
	}

	[Test]
	public async Task NonExportablePrivateKeysOfCertificatesAreNotImported()
	{
		if (!OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS())
		{
			Skip.Test("OpenSSL exports the key without Exportable.");
			return;
		}

		using ECDsa platform = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		using X509Certificate2 certificate = LoadPkcs12(platform, exportable: false);

		using (Assert.Multiple())
		{
			await Assert.That(SignatureKey.TryImportPrivateKey(certificate, out ISignatureKey? key)).IsFalse();
			await Assert.That(key).IsNull();
		}
	}

	// false is only for a key that the platform does not export, so an exported key that the import rejects throws.
	[Test]
	public async Task ExportablePrivateKeysOnOtherCurvesAreNotSupported()
	{
		if (OperatingSystem.IsMacOS())
		{
			Skip.Test("macOS has no ECDSA on brainpoolP256r1.");
			return;
		}

		using ECDsa platform = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
		using X509Certificate2 certificate = LoadPkcs12(platform, exportable: true);

		await Assert.That(() => SignatureKey.TryImportPrivateKey(certificate, out _)).ThrowsExactly<NotSupportedException>();
	}

	[Test]
	public async Task OnlyEcdsaPrivateKeysOfCertificatesAreSupported()
	{
		using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		using X509Certificate2 withKey = LoadPkcs12(ecdsa, exportable: true);
		using X509Certificate2 withoutKey = X509CertificateLoader.LoadCertificate(withKey.RawData);
		using RSA rsa = RSA.Create(2048);
		using X509Certificate2 rsaCertificate = new CertificateRequest("CN=RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

		using (Assert.Multiple())
		{
			await Assert.That(() => SignatureKey.TryImportPrivateKey(withoutKey, out _)).Throws<ArgumentException>().WithParameterName("certificate");
			await Assert.That(() => SignatureKey.TryImportPrivateKey(rsaCertificate, out _)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => SignatureKey.TryImportPrivateKey(null!, out _)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// A self-signed certificate with key as its private key, from a PKCS #12 file as a server loads one; macOS has no ephemeral key sets.
	private static X509Certificate2 LoadPkcs12(ECDsa key, bool exportable)
	{
		using X509Certificate2 created = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
		X509KeyStorageFlags flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
		return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12, "password"), "password", exportable ? flags | X509KeyStorageFlags.Exportable : flags);
	}
}
