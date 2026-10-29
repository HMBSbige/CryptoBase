namespace CryptoBase.X509;

/// <summary>
/// Represents an AlgorithmIdentifier (RFC 5280, Sec. 4.1.1.2): an algorithm and its parameters.
/// </summary>
public sealed class AlgorithmIdentifier
{
	// The identifiers in the DER that their specifications require, without parameters: ecdsa-with-SHA256, -SHA384 and -SHA512 (RFC 5758, Sec. 3.2) and id-ml-dsa-44, -65 and -87 (RFC 9881).
	private static readonly (SignatureAlgorithm Algorithm, AlgorithmIdentifier Identifier)[] SignatureAlgorithms =
	[
		(SignatureAlgorithm.EcdsaSha256, FromDer([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])),
		(SignatureAlgorithm.EcdsaSha384, FromDer([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03])),
		(SignatureAlgorithm.EcdsaSha512, FromDer([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04])),
		(SignatureAlgorithm.MLDsa44, FromDer([0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11])),
		(SignatureAlgorithm.MLDsa65, FromDer([0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])),
		(SignatureAlgorithm.MLDsa87, FromDer([0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13])),
	];

	private AlgorithmIdentifier(string oid, ReadOnlyMemory<byte> parameters, ReadOnlyMemory<byte> encoded)
	{
		Oid = oid;
		Parameters = parameters;
		Encoded = encoded;
	}

	/// <summary>
	/// Gets the algorithm as a dotted-decimal object identifier.
	/// </summary>
	public string Oid { get; }

	/// <summary>
	/// Gets the DER encoding of the parameters, or an empty value if they are absent.
	/// </summary>
	public ReadOnlyMemory<byte> Parameters { get; }

	/// <summary>
	/// Gets the DER encoding of the whole AlgorithmIdentifier.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the identifier that names a signature algorithm in X.509.
	/// </summary>
	/// <param name="algorithm">The signature algorithm: <see cref="SignatureAlgorithm.EcdsaSha256" />, <see cref="SignatureAlgorithm.EcdsaSha384" />, <see cref="SignatureAlgorithm.EcdsaSha512" />, <see cref="SignatureAlgorithm.MLDsa44" />, <see cref="SignatureAlgorithm.MLDsa65" /> or <see cref="SignatureAlgorithm.MLDsa87" />.</param>
	/// <returns>The identifier, without parameters.</returns>
	/// <exception cref="NotSupportedException"><paramref name="algorithm" /> is another value.</exception>
	public static AlgorithmIdentifier FromSignatureAlgorithm(SignatureAlgorithm algorithm)
	{
		foreach ((SignatureAlgorithm candidate, AlgorithmIdentifier identifier) in SignatureAlgorithms)
		{
			if (candidate == algorithm)
			{
				return identifier;
			}
		}

		throw new NotSupportedException($"The signature algorithm {algorithm} has no X.509 identifier in this version.");
	}

	/// <summary>
	/// Determines the signature algorithm that the identifier names.
	/// </summary>
	/// <remarks>The identifier matches only in the DER that the specification of the algorithm requires, which for every algorithm that <see cref="FromSignatureAlgorithm" /> accepts has no parameters.</remarks>
	/// <param name="algorithm">When this method returns <see langword="true" />, the signature algorithm.</param>
	/// <returns><see langword="true" /> if the identifier names a signature algorithm that <see cref="FromSignatureAlgorithm" /> accepts; otherwise, <see langword="false" />.</returns>
	public bool TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm)
	{
		foreach ((SignatureAlgorithm candidate, AlgorithmIdentifier identifier) in SignatureAlgorithms)
		{
			if (Encoded.Span.SequenceEqual(identifier.Encoded.Span))
			{
				algorithm = candidate;
				return true;
			}
		}

		algorithm = default;
		return false;
	}

	// SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }; the results are slices of the reader's memory.
	internal static AlgorithmIdentifier Read(ref DerReader reader)
	{
		DerReader contents = reader.ReadSequence(out ReadOnlyMemory<byte> encoded);
		string oid = contents.ReadObjectIdentifier();
		ReadOnlyMemory<byte> parameters = contents.HasData ? contents.ReadEncodedValue() : default;
		contents.ThrowIfNotEmpty();
		return new AlgorithmIdentifier(oid, parameters, encoded);
	}

	private static AlgorithmIdentifier FromDer(byte[] encoded)
	{
		DerReader reader = new(encoded);
		AlgorithmIdentifier identifier = Read(ref reader);
		reader.ThrowIfNotEmpty();
		return identifier;
	}
}
