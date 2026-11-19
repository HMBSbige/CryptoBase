namespace CryptoBase.X509;

/// <summary>
/// Represents the value of a basic constraints extension (RFC 5280, Sec. 4.2.1.9): whether the subject is a CA, and how many CA certificates may follow its certificate in a certification path.
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER, which omits a cA that is FALSE, its default, so a value that encodes it does not decode;
/// neither does a negative pathLenConstraint.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class BasicConstraints
{
	private BasicConstraints(bool certificateAuthority, int? pathLengthConstraint)
	{
		CertificateAuthority = certificateAuthority;
		PathLengthConstraint = pathLengthConstraint;
	}

	/// <summary>
	/// Gets cA: whether the subject is a CA, whose key may verify the signatures of certificates.
	/// </summary>
	public bool CertificateAuthority { get; }

	/// <summary>
	/// Gets pathLenConstraint, the most intermediate certificates that are not self-issued that may follow the certificate in a path, or <see langword="null" /> if it is absent, which imposes no limit.
	/// </summary>
	/// <remarks>
	/// A limit beyond <see cref="int.MaxValue" />, which no path reaches, is <see cref="int.MaxValue" />.
	/// The value is that of the encoding whatever <see cref="CertificateAuthority" /> is, though RFC 5280 gives it meaning only for a CA whose key usage asserts keyCertSign;
	/// the caller decides what to make of the others.
	/// </remarks>
	public int? PathLengthConstraint { get; }

	/// <summary>
	/// Decodes the DER-encoded value of a basic constraints extension.
	/// </summary>
	/// <param name="source">The contents of extnValue, a BasicConstraints, with nothing after it.</param>
	/// <returns>The decoded value.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded BasicConstraints.</exception>
	public static BasicConstraints Decode(ReadOnlySpan<byte> source)
	{
		try
		{
			return Read(source.ToArray());
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The basic constraints are invalid.", nameof(source), e);
		}
	}

	// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }; DER omits cA when it is FALSE.
	internal static BasicConstraints Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		bool certificateAuthority = sequence.ReadTrueOrAbsent();
		int? pathLengthConstraint = sequence.HasData ? sequence.ReadSaturatedInt32("The pathLenConstraint is negative.") : null;
		sequence.ThrowIfNotEmpty();
		return new BasicConstraints(certificateAuthority, pathLengthConstraint);
	}
}
