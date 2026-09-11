namespace CryptoBase.Hashes.Crc32;

internal struct Crc32TableSet
{
	internal InlineArray256<uint> Lookup;
	internal Crc32SlicingLookupBuffer SlicingLookup;
	internal Crc32BraidLookupBuffer FourWayBraidLookup;
	internal Crc32BraidLookupBuffer FiveWayBraidLookup;
}
