namespace CryptoBase.X509;

// A Name of RFC 5280, Sec. 4.1.2.4: SEQUENCE OF RelativeDistinguishedName, each a nonempty SET OF SEQUENCE { type OBJECT IDENTIFIER, value ANY }. Each value is read whole, as one DER element, without checking its contents.
internal static class X509Name
{
	public static bool IsEmpty(ReadOnlySpan<byte> encoded)
	{
		return encoded is [0x30, 0x00];
	}

	// The Name whole, a slice of the reader's memory.
	public static ReadOnlyMemory<byte> Read(ref DerReader reader)
	{
		DerReader name = reader.ReadSequence(out ReadOnlyMemory<byte> encoded);

		while (name.HasData)
		{
			DerReader relativeName = name.ReadSetOf();
			relativeName.ThrowIfEmpty();

			while (relativeName.HasData)
			{
				DerReader attribute = relativeName.ReadSequence();
				attribute.SkipObjectIdentifier();
				attribute.ReadEncodedValue();
				attribute.ThrowIfNotEmpty();
			}
		}

		return encoded;
	}
}
