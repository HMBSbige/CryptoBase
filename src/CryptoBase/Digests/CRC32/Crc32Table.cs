namespace CryptoBase.Digests.CRC32;

public class Crc32Table
{
	private const uint Polynomial = 0xEDB88320;
	private const uint PolynomialC = 0x82F63B78;

	private readonly uint[] _table;

	private Crc32Table(uint poly)
	{
		_table = new uint[16 * 256];

		for (uint i = 0; i < 256; ++i)
		{
			uint res = i;

			for (int j = 0; j < 16; ++j)
			{
				for (int k = 0; k < 8; ++k)
				{
					res = (res & 1) == 1 ? poly ^ res >> 1 : res >> 1;
				}

				_table[j * 256 + i] = res;
			}
		}
	}

	public uint Append(uint crc, ReadOnlySpan<byte> source)
	{
		int offset = 0;
		int length = source.Length;
		uint crcLocal = uint.MaxValue ^ crc;

		uint[] table = _table;

		while (length >= 16)
		{
			uint a = table[3 * 256 + source[offset + 12]]
					^ table[2 * 256 + source[offset + 13]]
					^ table[1 * 256 + source[offset + 14]]
					^ table[0 * 256 + source[offset + 15]];

			uint b = table[7 * 256 + source[offset + 8]]
					^ table[6 * 256 + source[offset + 9]]
					^ table[5 * 256 + source[offset + 10]]
					^ table[4 * 256 + source[offset + 11]];

			uint c = table[11 * 256 + source[offset + 4]]
					^ table[10 * 256 + source[offset + 5]]
					^ table[9 * 256 + source[offset + 6]]
					^ table[8 * 256 + source[offset + 7]];

			uint d = table[15 * 256 + ((byte)crcLocal ^ source[offset])]
					^ table[14 * 256 + ((byte)(crcLocal >> 8) ^ source[offset + 1])]
					^ table[13 * 256 + ((byte)(crcLocal >> 16) ^ source[offset + 2])]
					^ table[12 * 256 + (crcLocal >> 24 ^ source[offset + 3])];

			crcLocal = d ^ c ^ b ^ a;
			offset += 16;
			length -= 16;
		}

		while (--length >= 0)
		{
			crcLocal = table[(byte)(crcLocal ^ source[offset++])] ^ crcLocal >> 8;
		}

		return crcLocal ^ uint.MaxValue;
	}

	public static readonly Crc32Table Crc32 = new(Polynomial);
	public static readonly Crc32Table Crc32C = new(PolynomialC);
}
