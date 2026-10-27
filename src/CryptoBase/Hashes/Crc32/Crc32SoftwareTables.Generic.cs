namespace CryptoBase.Hashes.Crc32;

internal static class Crc32SoftwareTables<TAlgorithm> where TAlgorithm : unmanaged
{
	// ReSharper disable once StaticMemberInGenericType
	internal static Crc32TableSet Tables;

	static Crc32SoftwareTables()
	{
		Crc32SoftwareTables.Initialize(Crc32Engine.IsIeee<TAlgorithm>() ? 0xedb88320U : 0x82f63b78U, ref Tables);
	}
}
