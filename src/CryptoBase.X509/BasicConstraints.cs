namespace CryptoBase.X509;

// The value of a basic constraints extension (RFC 5280, Sec. 4.2.1.9), for certification path validation.
internal sealed class BasicConstraints
{
	private BasicConstraints(bool certificateAuthority, int? pathLengthConstraint)
	{
		CertificateAuthority = certificateAuthority;
		PathLengthConstraint = pathLengthConstraint;
	}

	// cA: whether the subject's key may verify certificate signatures.
	public bool CertificateAuthority { get; }

	// pathLenConstraint, or null if it is absent, which imposes no limit. A limit beyond int.MaxValue, which no path reaches, is int.MaxValue. It is returned whatever cA is, for the validator to judge.
	public int? PathLengthConstraint { get; }

	// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }; DER omits cA when it is FALSE.
	public static BasicConstraints Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		bool certificateAuthority = sequence.ReadTrueOrAbsent();
		int? pathLengthConstraint = null;

		if (sequence.HasData)
		{
			pathLengthConstraint = sequence.ReadSaturatedInt32("The pathLenConstraint is negative.");
		}

		sequence.ThrowIfNotEmpty();
		return new BasicConstraints(certificateAuthority, pathLengthConstraint);
	}
}
