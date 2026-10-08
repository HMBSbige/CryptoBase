using System.Buffers.Binary;
using System.Numerics;

namespace CryptoBase.Tests.Hashes.Blake2b;

// Direct transcription of the RFC 7693 compression function F.
internal static class Blake2bReference
{
	private static ReadOnlySpan<ulong> IV =>
	[
		0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
		0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
	];

	private static ReadOnlySpan<byte> Sigma =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
		11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
		7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
		9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
		2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
		12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
		13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
		6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
		10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
	];

	public static void Compress(Span<ulong> h, ReadOnlySpan<byte> block, UInt128 counter, ulong finalFlag)
	{
		Span<ulong> v = stackalloc ulong[16];
		Span<ulong> m = stackalloc ulong[16];

		for (int i = 0; i < 16; ++i)
		{
			m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * sizeof(ulong)));
		}

		h.CopyTo(v);
		IV.CopyTo(v.Slice(8));
		v[12] ^= (ulong)counter;
		v[13] ^= (ulong)(counter >> 64);
		v[14] ^= finalFlag;

		for (int round = 0; round < 12; ++round)
		{
			ReadOnlySpan<byte> s = Sigma.Slice(round % 10 * 16, 16);
			G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
			G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
			G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
			G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
			G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
			G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
			G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
			G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
		}

		for (int i = 0; i < 8; ++i)
		{
			h[i] ^= v[i] ^ v[i + 8];
		}
	}

	private static void G(Span<ulong> v, int a, int b, int c, int d, ulong x, ulong y)
	{
		v[a] = v[a] + v[b] + x;
		v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
		v[c] += v[d];
		v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
		v[a] = v[a] + v[b] + y;
		v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
		v[c] += v[d];
		v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
	}
}
