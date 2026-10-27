namespace CryptoBase.Hashes.Crc32;

internal struct Crc32TableSet
{
	// The byte-wise table, followed by the seven further slicing-by-8 tables.
	internal InlineArray2048<uint> Lookup;
	internal InlineArray2048<uint> FourWayBraidLookup;
	internal InlineArray2048<uint> FiveWayBraidLookup;
}
