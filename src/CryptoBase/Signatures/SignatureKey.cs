using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.Signatures.Rsa;
using CryptoBase.SM2;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace CryptoBase.Signatures;

/// <summary>
/// Imports a signature key as the type of the algorithm that its encoding names.
/// </summary>
/// <remarks>
/// <para>
/// id-ecPublicKey with the named curve P-256, P-384 or P-521 gives <see cref="EcdsaP256" />, <see cref="EcdsaP384" /> or <see cref="EcdsaP521" />, and with the named curve of SM2, 1.2.156.10197.1.301, <see cref="SM2Key" />. id-Ed25519 or id-Ed448 gives <see cref="Ed25519" /> or <see cref="Ed448" />, id-ml-dsa-44, id-ml-dsa-65 or id-ml-dsa-87 gives <see cref="MLDsa44" />, <see cref="MLDsa65" /> or <see cref="MLDsa87" />,
/// and rsaEncryption with NULL parameters or id-RSASSA-PSS gives <see cref="RsaKey" />.
/// The AlgorithmIdentifier must match one of these in DER whole, so a key of another algorithm, or of one of these with other parameters such as an explicit curve, throws <see cref="NotSupportedException" />; id-RSASSA-PSS alone matches by its OID, and <see cref="RsaKey" /> checks its parameters.
/// </para>
/// <para>
/// The type then imports the key and checks the rest of the encoding, as its own import method does.
/// </para>
/// </remarks>
public static class SignatureKey
{
	private const string PublicKeyLabel = "PUBLIC KEY";
	private const string PrivateKeyLabel = "PRIVATE KEY";
	private const string ECPrivateKeyLabel = "EC PRIVATE KEY";
	private const string SM2PrivateKeyLabel = "SM2 PRIVATE KEY";
	private const string RsaPublicKeyLabel = "RSA PUBLIC KEY";
	private const string RsaPrivateKeyLabel = "RSA PRIVATE KEY";
	private const string ECPublicKeyOid = "1.2.840.10045.2.1";

	private static Asn1Tag ParametersTag => new(TagClass.ContextSpecific, 0, true);

	/// <summary>
	/// Imports a public key from a DER-encoded X.509 SubjectPublicKeyInfo (RFC 5280).
	/// </summary>
	/// <param name="source">The SubjectPublicKeyInfo, with nothing after it.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not valid DER or holds an invalid key.</exception>
	/// <exception cref="NotSupportedException">The key algorithm is not supported, or <see cref="RsaKey.ImportSubjectPublicKeyInfo" /> does not support the RSA key.</exception>
	public static ISignatureKey ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		return Import(source, privateKey: false);
	}

	/// <summary>
	/// Imports a private key from a DER-encoded PKCS #8 PrivateKeyInfo or OneAsymmetricKey (RFC 5958).
	/// </summary>
	/// <remarks>The key is validated before use; implementation-owned key material is erased if it is invalid.</remarks>
	/// <param name="source">The PrivateKeyInfo, with nothing after it.</param>
	/// <returns>An instance that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not valid DER or holds an invalid key.</exception>
	/// <exception cref="NotSupportedException">The key algorithm is not supported, or <see cref="RsaKey.ImportPkcs8PrivateKey" /> does not support the RSA key.</exception>
	public static ISignatureKey ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		return Import(source, privateKey: true);
	}

	/// <summary>
	/// Imports a key from the one PEM block (RFC 7468) labeled PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, RSA PRIVATE KEY, EC PRIVATE KEY or SM2 PRIVATE KEY in a text.
	/// </summary>
	/// <remarks>
	/// <para>
	/// An RSA PUBLIC KEY or RSA PRIVATE KEY block holds a PKCS #1 RSAPublicKey or RSAPrivateKey (RFC 8017, Appendices A.1.1 and A.1.2), which <see cref="RsaKey.ImportRsaPublicKey" /> or <see cref="RsaKey.ImportRsaPrivateKey" /> imports.
	/// An EC PRIVATE KEY block holds an ECPrivateKey (RFC 5915, Sec. 4), which is imported as the PrivateKeyInfo that carries it with id-ecPublicKey and its parameters (Sec. 1). Its parameters, which RFC 5915 requires, must therefore name P-256, P-384, P-521 or the curve of SM2.
	/// An SM2 PRIVATE KEY block holds the same ECPrivateKey, and its parameters must name the curve of SM2.
	/// </para>
	/// <para>
	/// Other blocks, such as EC PARAMETERS, and the text around the blocks are ignored. Encrypted keys are not supported: neither the label ENCRYPTED PRIVATE KEY nor an RSA PRIVATE KEY, EC PRIVATE KEY or SM2 PRIVATE KEY block with the Proc-Type and DEK-Info headers of RFC 1421, which RFC 7468 does not permit. The decoded key is erased after the import.
	/// </para>
	/// </remarks>
	/// <param name="source">The text.</param>
	/// <returns>An instance that holds only the public key for PUBLIC KEY and RSA PUBLIC KEY, or the private key and the public key for the other labels.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has no such block or more than one, or the block is not valid DER, holds an invalid key or, for EC PRIVATE KEY and SM2 PRIVATE KEY, has no parameters, or for SM2 PRIVATE KEY names another curve.</exception>
	/// <exception cref="NotSupportedException">The key algorithm, the RSA key, or the curve of an EC PRIVATE KEY is not supported.</exception>
	public static ISignatureKey ImportFromPem(ReadOnlySpan<char> source)
	{
		PemReader reader = new(source);
		ReadOnlySpan<char> keyLabel = default;
		ReadOnlySpan<char> keyData = default;
		int keyLength = 0;

		while (reader.TryRead(out ReadOnlySpan<char> label, out ReadOnlySpan<char> base64Data, out int decodedLength))
		{
			if (label is not (PublicKeyLabel or PrivateKeyLabel or RsaPublicKeyLabel or RsaPrivateKeyLabel or ECPrivateKeyLabel or SM2PrivateKeyLabel))
			{
				continue;
			}

			if (!keyLabel.IsEmpty)
			{
				throw new ArgumentException("The text holds more than one PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, RSA PRIVATE KEY, EC PRIVATE KEY or SM2 PRIVATE KEY block.", nameof(source));
			}

			keyLabel = label;
			keyData = base64Data;
			keyLength = decodedLength;
		}

		if (keyLabel.IsEmpty)
		{
			throw new ArgumentException("The text holds no PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, RSA PRIVATE KEY, EC PRIVATE KEY or SM2 PRIVATE KEY block. Encrypted keys are not supported.", nameof(source));
		}

		using CryptoBuffer<byte> der = new(keyLength);
		PemReader.Decode(keyData, der.Span);

		return keyLabel switch
		{
			PublicKeyLabel => Import(der.Span, privateKey: false),
			PrivateKeyLabel => Import(der.Span, privateKey: true),
			RsaPublicKeyLabel => RsaKey.ImportRsaPublicKey(der.Span),
			RsaPrivateKeyLabel => RsaKey.ImportRsaPrivateKey(der.Span),
			ECPrivateKeyLabel => ImportECPrivateKey(der.Span, sm2: false),
			_ => ImportECPrivateKey(der.Span, sm2: true)
		};
	}

	/// <summary>
	/// Imports the private key of a certificate if the platform exports it.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The certificate's key must be an EC key on P-256, P-384, P-521 or the curve of SM2, or RSA. The platform exports it as a PKCS #8 PrivateKeyInfo, which <see cref="ImportPkcs8PrivateKey" /> imports, and the exported encoding is erased after the import.
	/// The result holds a copy of the private key, so it does not depend on <paramref name="certificate" />.
	/// </para>
	/// <para>
	/// The platform does not export some keys, such as one in a smart card or TPM, or on Windows and macOS one of a PKCS #12 file loaded without <see cref="X509KeyStorageFlags.Exportable" />; such a key signs only through the platform, as GetSignaturePrivateKey of CryptoBase.X509 gives it.
	/// </para>
	/// </remarks>
	/// <param name="certificate">The certificate.</param>
	/// <param name="key">When this method returns <see langword="true" />, an instance that holds the private key and the public key; otherwise, <see langword="null" />.</param>
	/// <returns><see langword="true" /> if the platform exports the private key; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="certificate" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="certificate" /> has no private key.</exception>
	/// <exception cref="NotSupportedException">The key is neither ECDSA nor RSA, or the platform exports a key that <see cref="ImportPkcs8PrivateKey" /> does not support, such as an EC key that is not on P-256, P-384, P-521 or the curve of SM2.</exception>
	/// <exception cref="CryptographicException">The platform cannot open the private key.</exception>
	public static bool TryImportPrivateKey(X509Certificate2 certificate, [NotNullWhen(true)] out ISignatureKey? key)
	{
		ArgumentNullException.ThrowIfNull(certificate);

		if (!certificate.HasPrivateKey)
		{
			throw new ArgumentException("The certificate has no private key.", nameof(certificate));
		}

		using AsymmetricAlgorithm platform = (AsymmetricAlgorithm?)certificate.GetECDsaPrivateKey() ?? certificate.GetRSAPrivateKey() ?? throw new NotSupportedException("Only ECDSA and RSA private keys are supported.");
		byte[] pkcs8;

		try
		{
			pkcs8 = platform.ExportPkcs8PrivateKey();
		}
		catch (CryptographicException)
		{
			// The platform does not export the key.
			key = null;
			return false;
		}

		try
		{
			key = ImportPkcs8PrivateKey(pkcs8);
			return true;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(pkcs8);
		}
	}

	// source is a SubjectPublicKeyInfo, or a PrivateKeyInfo if privateKey is true.
	private static ISignatureKey Import(ReadOnlySpan<byte> source, bool privateKey)
	{
		ReadOnlySpan<byte> algorithm = ReadAlgorithmIdentifier(source, privateKey);

		return algorithm switch
		{
			_ when algorithm.SequenceEqual(EcdsaP256.AlgorithmIdentifier) => Import<EcdsaP256>(source, privateKey),
			_ when algorithm.SequenceEqual(EcdsaP384.AlgorithmIdentifier) => Import<EcdsaP384>(source, privateKey),
			_ when algorithm.SequenceEqual(EcdsaP521.AlgorithmIdentifier) => Import<EcdsaP521>(source, privateKey),
			_ when algorithm.SequenceEqual(SM2Key.AlgorithmIdentifier) => Import<SM2Key>(source, privateKey),
			_ when algorithm.SequenceEqual(Ed25519Key.AlgorithmIdentifier) => Import<Ed25519>(source, privateKey),
			_ when algorithm.SequenceEqual(Ed448Key.AlgorithmIdentifier) => Import<Ed448>(source, privateKey),
			_ when algorithm.SequenceEqual(MLDsa44Parameters.AlgorithmIdentifier) => Import<MLDsa44>(source, privateKey),
			_ when algorithm.SequenceEqual(MLDsa65Parameters.AlgorithmIdentifier) => Import<MLDsa65>(source, privateKey),
			_ when algorithm.SequenceEqual(MLDsa87Parameters.AlgorithmIdentifier) => Import<MLDsa87>(source, privateKey),
			_ when algorithm.SequenceEqual(RsaKeyDer.RsaEncryption) || RsaKeyDer.IsRsassaPss(algorithm) => Import<RsaKey>(source, privateKey),
			_ => throw new NotSupportedException("The key algorithm is not supported.")
		};
	}

	private static ISignatureKey Import<T>(ReadOnlySpan<byte> source, bool privateKey) where T : class, ISignatureKey<T>
	{
		return privateKey ? T.ImportPkcs8PrivateKey(source) : T.ImportSubjectPublicKeyInfo(source);
	}

	// source is an ECPrivateKey, imported as the PrivateKeyInfo that carries it under id-ecPublicKey with its parameters (RFC 5915, Sec. 1); the PrivateKeyInfo is erased after the import.
	// sm2 requires the parameters to name the curve of SM2, as the label SM2 PRIVATE KEY does.
	private static ISignatureKey ImportECPrivateKey(ReadOnlySpan<byte> source, bool sm2)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier(ECPublicKeyOid);
			writer.WriteEncodedValue(ReadParameters(source));
		}

		byte[] algorithmIdentifier = writer.Encode();

		if (sm2 && !algorithmIdentifier.AsSpan().SequenceEqual(SM2Key.AlgorithmIdentifier))
		{
			throw new ArgumentException("The SM2 PRIVATE KEY block names another curve.", nameof(source));
		}

		using CryptoBuffer<byte> privateKeyInfo = new(KeyInfoDer.GetPrivateKeyInfoLength(algorithmIdentifier, source.Length));
		KeyInfoDer.WritePrivateKeyInfo(algorithmIdentifier, source, privateKeyInfo.Span);
		return Import(privateKeyInfo.Span, privateKey: true);
	}

	// The AlgorithmIdentifier, checked to be one, of the SubjectPublicKeyInfo or the PrivateKeyInfo that fills source. The importer checks the rest.
	private static ReadOnlySpan<byte> ReadAlgorithmIdentifier(ReadOnlySpan<byte> source, bool privateKey)
	{
		try
		{
			ValueAsnReader reader = new(source, AsnEncodingRules.DER);
			ValueAsnReader contents = reader.ReadSequence();
			reader.ThrowIfNotEmpty();

			if (privateKey)
			{
				contents.ReadIntegerBytes();
			}

			ReadOnlySpan<byte> algorithmIdentifier = contents.PeekEncodedValue();
			ValueAsnReader fields = contents.ReadSequence();
			fields.ReadObjectIdentifier();

			if (fields.HasData)
			{
				fields.ReadEncodedValue();
				fields.ThrowIfNotEmpty();
			}

			return algorithmIdentifier;
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The key encoding is invalid.", nameof(source), e);
		}
	}

	// The parameters, checked to be one value, of the ECPrivateKey that fills source; version and privateKey before them are skipped. The importer checks the rest.
	private static ReadOnlySpan<byte> ReadParameters(ReadOnlySpan<byte> source)
	{
		try
		{
			ValueAsnReader reader = new(source, AsnEncodingRules.DER);
			ValueAsnReader contents = reader.ReadSequence();
			reader.ThrowIfNotEmpty();
			contents.ReadEncodedValue();
			contents.ReadEncodedValue();
			ValueAsnReader parameters = contents.ReadSequence(ParametersTag);
			ReadOnlySpan<byte> value = parameters.ReadEncodedValue();
			parameters.ThrowIfNotEmpty();
			return value;
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The key encoding is invalid.", nameof(source), e);
		}
	}
}
