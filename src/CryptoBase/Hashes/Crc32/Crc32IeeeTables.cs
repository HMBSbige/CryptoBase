namespace CryptoBase.Hashes.Crc32;

internal static class Crc32IeeeTables
{
	internal static Crc32TableSet Tables;

	static Crc32IeeeTables()
	{
		Crc32SoftwareTables.Initialize(0xedb88320U, ref Tables.Lookup, ref Tables.SlicingLookup, ref Tables.FourWayBraidLookup, ref Tables.FiveWayBraidLookup);
	}
}
