namespace CryptoBase.Hashes.Crc32;

[InlineArray(sizeof(ulong) * Crc32SoftwareTables.TableSize)]
internal struct Crc32BraidLookupBuffer
{
	private uint t;
}
