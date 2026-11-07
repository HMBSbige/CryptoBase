using System.Buffers.Binary;
using System.Numerics;

namespace CryptoBase.Tests.Hashes.SM3;

// The compression function and the hash of the SM3 standard, Sec. 5, written out word by word.
public static class SM3Reference
{
	public static readonly uint[] InitialValue = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E];

	public static void Compress(uint[] v, ReadOnlySpan<uint> block)
	{
		uint[] w = new uint[68];
		block.Slice(0, 16).CopyTo(w);

		for (int j = 16; j < 68; ++j)
		{
			w[j] = P1(w[j - 16] ^ w[j - 9] ^ BitOperations.RotateLeft(w[j - 3], 15)) ^ BitOperations.RotateLeft(w[j - 13], 7) ^ w[j - 6];
		}

		uint a = v[0], b = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h = v[7];

		for (int j = 0; j < 64; ++j)
		{
			uint t = j < 16 ? 0x79CC4519U : 0x7A879D8AU;
			uint ss1 = BitOperations.RotateLeft(BitOperations.RotateLeft(a, 12) + e + BitOperations.RotateLeft(t, j % 32), 7);
			uint ss2 = ss1 ^ BitOperations.RotateLeft(a, 12);
			uint ff = j < 16 ? a ^ b ^ c : a & b | a & c | b & c;
			uint gg = j < 16 ? e ^ f ^ g : e & f | ~e & g;
			uint tt1 = ff + d + ss2 + (w[j] ^ w[j + 4]);
			uint tt2 = gg + h + ss1 + w[j];
			d = c;
			c = BitOperations.RotateLeft(b, 9);
			b = a;
			a = tt1;
			h = g;
			g = BitOperations.RotateLeft(f, 19);
			f = e;
			e = P0(tt2);
		}

		v[0] ^= a;
		v[1] ^= b;
		v[2] ^= c;
		v[3] ^= d;
		v[4] ^= e;
		v[5] ^= f;
		v[6] ^= g;
		v[7] ^= h;
	}

	public static byte[] Hash(ReadOnlySpan<byte> message)
	{
		int blockCount = (message.Length + 9 + 63) / 64;
		byte[] padded = new byte[64 * blockCount];
		message.CopyTo(padded);
		padded[message.Length] = 0x80;
		BinaryPrimitives.WriteUInt64BigEndian(padded.AsSpan(padded.Length - 8), (ulong)message.Length * 8);
		uint[] v = [.. InitialValue];
		uint[] block = new uint[16];

		for (int offset = 0; offset < padded.Length; offset += 64)
		{
			for (int i = 0; i < 16; ++i)
			{
				block[i] = BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan(offset + 4 * i));
			}

			Compress(v, block);
		}

		byte[] hash = new byte[32];

		for (int i = 0; i < 8; ++i)
		{
			BinaryPrimitives.WriteUInt32BigEndian(hash.AsSpan(4 * i), v[i]);
		}

		return hash;
	}

	private static uint P0(uint x)
	{
		return x ^ BitOperations.RotateLeft(x, 9) ^ BitOperations.RotateLeft(x, 17);
	}

	private static uint P1(uint x)
	{
		return x ^ BitOperations.RotateLeft(x, 15) ^ BitOperations.RotateLeft(x, 23);
	}
}
