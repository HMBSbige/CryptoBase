namespace CryptoBase.X509;

/// <summary>
/// Represents a SubjectPublicKeyInfo (RFC 5280, Sec. 4.1.2.7): the algorithm of a public key and the key.
/// </summary>
/// <remarks>Decoding checks the structure, not the key; <see cref="ISignatureKey{TSelf}.ImportSubjectPublicKeyInfo" /> of a key type imports the key from <see cref="Encoded" />.</remarks>
public sealed class SubjectPublicKeyInfo
{
	private SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> encoded)
	{
		Algorithm = algorithm;
		PublicKey = publicKey;
		Encoded = encoded;
	}

	/// <summary>
	/// Gets the algorithm of the key.
	/// </summary>
	public AlgorithmIdentifier Algorithm { get; }

	/// <summary>
	/// Gets the subjectPublicKey, the bytes of its BIT STRING.
	/// </summary>
	public ReadOnlyMemory<byte> PublicKey { get; }

	/// <summary>
	/// Gets the DER encoding of the whole SubjectPublicKeyInfo.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Decodes a DER-encoded SubjectPublicKeyInfo.
	/// </summary>
	/// <param name="source">The SubjectPublicKeyInfo, with nothing after it.</param>
	/// <returns>The decoded SubjectPublicKeyInfo, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded SubjectPublicKeyInfo whose subjectPublicKey is a whole number of bytes.</exception>
	public static SubjectPublicKeyInfo Decode(ReadOnlySpan<byte> source)
	{
		return Decode(source.ToArray(), nameof(source));
	}

	// encoded is owned by the new instance.
	internal static SubjectPublicKeyInfo Decode(byte[] encoded, string parameterName)
	{
		try
		{
			DerReader reader = new(encoded);
			SubjectPublicKeyInfo info = Read(ref reader);
			reader.ThrowIfNotEmpty();
			return info;
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The SubjectPublicKeyInfo is invalid.", parameterName, e);
		}
	}

	// SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }; the results are slices of the reader's memory.
	internal static SubjectPublicKeyInfo Read(ref DerReader reader)
	{
		DerReader contents = reader.ReadSequence(out ReadOnlyMemory<byte> encoded);
		AlgorithmIdentifier algorithm = AlgorithmIdentifier.Read(ref contents);
		ReadOnlyMemory<byte> publicKey = contents.ReadBitString();
		contents.ThrowIfNotEmpty();
		return new SubjectPublicKeyInfo(algorithm, publicKey, encoded);
	}
}
