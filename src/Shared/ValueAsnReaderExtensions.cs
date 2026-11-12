namespace CryptoBase.Internal;

// Reads that ValueAsnReader lacks. Malformed input throws AsnContentException.
internal static class ValueAsnReaderExtensions
{
	extension(scoped ref ValueAsnReader reader)
	{
		public bool PeekTagIs(Asn1Tag tag)
		{
			return reader.HasData && reader.PeekTag() == tag;
		}

		// A SEQUENCE, whole.
		public ReadOnlySpan<byte> ReadEncodedSequence()
		{
			if (reader.PeekTag() != Asn1Tag.Sequence)
			{
				throw new AsnContentException();
			}

			return reader.ReadEncodedValue();
		}

		public int ReadInt32()
		{
			return reader.TryReadInt32(out int value) ? value : throw new AsnContentException();
		}

		// The contents of an INTEGER that is not negative, which DER requires to be minimal.
		public ReadOnlySpan<byte> ReadUnsignedInteger()
		{
			ReadOnlySpan<byte> value = reader.ReadIntegerBytes();
			return value[0] < 0x80 ? value : throw new AsnContentException();
		}
	}
}
