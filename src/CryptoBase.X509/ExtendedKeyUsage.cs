namespace CryptoBase.X509;

// The value of an extended key usage extension (RFC 5280, Sec. 4.2.1.12), for certification path validation.
internal sealed class ExtendedKeyUsage
{
	public const string AnyExtendedKeyUsage = "2.5.29.37.0";

	private readonly string[] _purposes;

	private ExtendedKeyUsage(string[] purposes)
	{
		_purposes = purposes;
	}

	// The KeyPurposeIds as dotted-decimal object identifiers, in the order of the encoding, repeats included. Whether anyExtendedKeyUsage stands for a purpose that is absent is for the validator to decide.
	public IReadOnlyList<string> Purposes => _purposes;

	// Searches the array, which the interface would enumerate with an allocated enumerator.
	public bool Contains(string purpose)
	{
		foreach (string candidate in _purposes)
		{
			if (candidate == purpose)
			{
				return true;
			}
		}

		return false;
	}

	// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId, and KeyPurposeId ::= OBJECT IDENTIFIER.
	public static ExtendedKeyUsage Read(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		DerReader sequence = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		sequence.ThrowIfEmpty();
		List<string> purposes = [];

		while (sequence.HasData)
		{
			purposes.Add(sequence.ReadObjectIdentifier());
		}

		return new ExtendedKeyUsage([.. purposes]);
	}
}
