namespace CryptoBase.Hashes.Crc32;

internal static class Crc32CastagnoliTables
{
	internal static Crc32TableSet Tables;

	static Crc32CastagnoliTables()
	{
		Crc32SoftwareTables.Initialize(0x82f63b78U, ref Tables.Lookup, ref Tables.SlicingLookup, ref Tables.FourWayBraidLookup, ref Tables.FiveWayBraidLookup);
	}
}
