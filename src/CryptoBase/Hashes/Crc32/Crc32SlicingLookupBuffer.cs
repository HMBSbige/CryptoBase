namespace CryptoBase.Hashes.Crc32;

[InlineArray((sizeof(ulong) - 1) * Crc32SoftwareTables.TableSize)]
internal struct Crc32SlicingLookupBuffer
{
	private uint t;
}
