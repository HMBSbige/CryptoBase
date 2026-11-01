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
		DerReader reader = new(value);
		DerReader sequence = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		bool certificateAuthority = sequence.PeekTagIs(Asn1Tag.Boolean);

		if (certificateAuthority && !sequence.ReadBoolean())
		{
			throw new AsnContentException();
		}

		int? pathLengthConstraint = null;

		if (sequence.HasData)
		{
			ReadOnlySpan<byte> integer = sequence.ReadIntegerBytes().Span;

			if (integer[0] >= 0x80)
			{
				throw new AsnContentException("The pathLenConstraint is negative.");
			}

			long limit = 0;

			foreach (byte octet in integer)
			{
				limit = Math.Min(limit << 8 | octet, int.MaxValue);
			}

			pathLengthConstraint = (int)limit;
		}

		sequence.ThrowIfNotEmpty();
		return new BasicConstraints(certificateAuthority, pathLengthConstraint);
	}
}
