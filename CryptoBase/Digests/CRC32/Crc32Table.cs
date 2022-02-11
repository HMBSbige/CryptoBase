using System.Runtime.Intrinsics;

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
			var res = i;
			for (var j = 0; j < 16; ++j)
			{
				for (var k = 0; k < 8; ++k)
				{
					res = (res & 1) == 1 ? poly ^ res >> 1 : res >> 1;
				}

				_table[j * 256 + i] = res;
			}
		}
	}

	public uint Append(uint crc, ReadOnlySpan<byte> source)
	{
		var offset = 0;
		var length = source.Length;
		var crcLocal = uint.MaxValue ^ crc;

		var table = _table;
		while (length >= 16)
		{
			var a = table[3 * 256 + source[offset + 12]]
				^ table[2 * 256 + source[offset + 13]]
				^ table[1 * 256 + source[offset + 14]]
				^ table[0 * 256 + source[offset + 15]];

			var b = table[7 * 256 + source[offset + 8]]
				^ table[6 * 256 + source[offset + 9]]
				^ table[5 * 256 + source[offset + 10]]
				^ table[4 * 256 + source[offset + 11]];

			var c = table[11 * 256 + source[offset + 4]]
				^ table[10 * 256 + source[offset + 5]]
				^ table[9 * 256 + source[offset + 6]]
				^ table[8 * 256 + source[offset + 7]];

			var d = table[15 * 256 + ((byte)crcLocal ^ source[offset])]
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

	public static readonly Vector128<ulong> Mask32 = Vector128.Create(0x00000000ffffffff, 0x0000000000000000).AsUInt64();

	#region Constants_CRC32

	// [x**(4*128+32) mod P(x) << 32)]'  << 1   = 0x154442bd4
	// [(x**(4*128-32) mod P(x) << 32)]' << 1   = 0x1c6e41596
	public static readonly Vector128<ulong> K1K2 = Vector128.Create(0x0000000154442bd4, 0x00000001c6e41596).AsUInt64();

	// [(x**(128+32) mod P(x) << 32)]'   << 1   = 0x1751997d0
	// [(x**(128-32) mod P(x) << 32)]'   << 1   = 0x0ccaa009e
	public static readonly Vector128<ulong> K3K4 = Vector128.Create(0x00000001751997d0, 0x00000000ccaa009e).AsUInt64();

	// [(x**64 mod P(x) << 32)]'         << 1   = 0x163cd6124
	public static readonly Vector128<ulong> K5 = Vector128.Create(0x0000000163cd6124, 0x0000000000000000).AsUInt64();

	// P(x)' = 0x1db710641
	// u' = (x**64 / P(x))' = 0x1F7011641
	public static readonly Vector128<ulong> RU = Vector128.Create(0x00000001db710641, 0x00000001f7011641).AsUInt64();

	#endregion

	#region Constants_CRC32C

	public static readonly Vector128<ulong> K1K2C = Vector128.Create(0x00000000740eef02, 0x000000009e4addf8).AsUInt64();
	public static readonly Vector128<ulong> K3K4C = Vector128.Create(0x00000000f20c0dfe, 0x000000014cd00bd6).AsUInt64();
	public static readonly Vector128<ulong> K5C = Vector128.Create(0x00000000dd45aab8, 0x0000000000000000).AsUInt64();
	public static readonly Vector128<ulong> RUC = Vector128.Create(0x0000000105ec76f1, 0x00000000dea713f1).AsUInt64();

	#endregion
}
