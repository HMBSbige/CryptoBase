namespace CryptoBase.X509;

// The value of a basic constraints extension (RFC 5280, Sec. 4.2.1.9), for certification path validation.
internal sealed class BasicConstraints(bool certificateAuthority, int? pathLengthConstraint)
{
	// cA: whether the subject's key may verify certificate signatures.
	public bool CertificateAuthority { get; } = certificateAuthority;

	// pathLenConstraint, or null if it is absent, which imposes no limit. A limit beyond int.MaxValue, which no path reaches, is int.MaxValue. It is returned whatever cA is, for the validator to judge.
	public int? PathLengthConstraint { get; } = pathLengthConstraint;

	// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }; DER omits cA when it is FALSE.
	public static BasicConstraints Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		bool certificateAuthority = sequence.ReadTrueOrAbsent();
		int? pathLengthConstraint = sequence.HasData ? sequence.ReadSaturatedInt32("The pathLenConstraint is negative.") : null;
		sequence.ThrowIfNotEmpty();
		return new BasicConstraints(certificateAuthority, pathLengthConstraint);
	}
}
