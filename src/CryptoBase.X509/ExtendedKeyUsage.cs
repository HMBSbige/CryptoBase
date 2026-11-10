namespace CryptoBase.X509;

// The value of an extended key usage extension (RFC 5280, Sec. 4.2.1.12), for certification path validation.
internal sealed class ExtendedKeyUsage(string[] purposes)
{
	public const string AnyExtendedKeyUsage = "2.5.29.37.0";

	// The KeyPurposeIds as dotted-decimal object identifiers, in the order of the encoding, repeats included. Whether anyExtendedKeyUsage stands for a purpose that is absent is for the validator to decide.
	public IReadOnlyList<string> Purposes => purposes;

	// Searches the array, which the interface would enumerate with an allocated enumerator.
	public bool Contains(string purpose)
	{
		return purposes.AsSpan().Contains(purpose);
	}

	// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId, and KeyPurposeId ::= OBJECT IDENTIFIER.
	public static ExtendedKeyUsage Read(ReadOnlyMemory<byte> value)
	{
		return new ExtendedKeyUsage([.. DerReader.ReadSoleSequenceOf(value, static (ref sequence) => sequence.ReadObjectIdentifier())]);
	}
}
