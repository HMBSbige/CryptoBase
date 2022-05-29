namespace CryptoBase.Digests.CRC32C;

public class Crc32CSF : Crc32SF
{
	public override string Name => @"CRC-32C";

	protected override Crc32Table Table => Crc32Table.Crc32C;
}
