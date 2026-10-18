using System.Buffers.Binary;
using System.Numerics;

namespace CryptoBase.Tests.Hashes.Sha3;

// A direct transcription of FIPS 202 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) that shares no code with the library:
// it derives the round constants with Algorithm 5 and the ρ offsets with Algorithm 2 instead of copying tables.
internal static class KeccakReference
{
	// The suffix bits of Sec. 6.1 and 6.2 followed by the first pad10*1 bit, as in Appendix B.2, Table 6.
	public const byte Sha3DomainSeparator = 0x06;
	public const byte ShakeDomainSeparator = 0x1F;

	private const int Width = 5;
	private const int LaneSize = 64;
	private const int Rounds = 24;

	private static readonly ulong[] RoundConstants = CreateRoundConstants();
	private static readonly int[] RhoOffsets = CreateRhoOffsets();

	public static byte[] Sha3(ReadOnlySpan<byte> message, int hashLength)
	{
		return Sponge(message, Sha3Rate(hashLength), Sha3DomainSeparator, hashLength);
	}

	// HMAC per FIPS 198-1 with the input block size B of FIPS 202, Table 3, which is the rate.
	public static byte[] HmacSha3(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, int hashLength)
	{
		int blockSize = Sha3Rate(hashLength);
		byte[] normalizedKey = key.Length > blockSize ? Sha3(key, hashLength) : key.ToArray();
		byte[] innerPad = new byte[blockSize];
		byte[] outerPad = new byte[blockSize];

		for (int i = 0; i < blockSize; ++i)
		{
			byte keyByte = i < normalizedKey.Length ? normalizedKey[i] : (byte)0;
			innerPad[i] = (byte)(keyByte ^ 0x36);
			outerPad[i] = (byte)(keyByte ^ 0x5C);
		}

		byte[] innerHash = Sha3(TestUtils.Concat(innerPad, message), hashLength);
		return Sha3(TestUtils.Concat(outerPad, innerHash), hashLength);
	}

	public static int Sha3Rate(int hashLength)
	{
		return 200 - 2 * hashLength;
	}

	// SPONGE[KECCAK-p[1600, 24], pad10*1, r] from Algorithm 8, on byte strings whose suffix bits fit in domainSeparator.
	public static byte[] Sponge(ReadOnlySpan<byte> message, int rateInBytes, byte domainSeparator, int outputLength)
	{
		byte[] padded = new byte[(message.Length / rateInBytes + 1) * rateInBytes];
		message.CopyTo(padded);
		padded[message.Length] ^= domainSeparator;
		padded[^1] ^= 0x80;

		ulong[] state = new ulong[Width * Width];

		for (int offset = 0; offset < padded.Length; offset += rateInBytes)
		{
			for (int lane = 0; lane < rateInBytes / sizeof(ulong); ++lane)
			{
				state[lane] ^= BinaryPrimitives.ReadUInt64LittleEndian(padded.AsSpan(offset + lane * sizeof(ulong)));
			}

			Permute(state);
		}

		byte[] output = new byte[outputLength];
		byte[] block = new byte[state.Length * sizeof(ulong)];

		for (int offset = 0; ; offset += rateInBytes)
		{
			for (int lane = 0; lane < state.Length; ++lane)
			{
				BinaryPrimitives.WriteUInt64LittleEndian(block.AsSpan(lane * sizeof(ulong)), state[lane]);
			}

			int length = Math.Min(rateInBytes, outputLength - offset);
			block.AsSpan(0, length).CopyTo(output.AsSpan(offset));

			if (offset + length == outputLength)
			{
				return output;
			}

			Permute(state);
		}
	}

	// KECCAK-p[1600, 24] from Algorithm 7; lane A[x, y] is state[x + 5y], and bit z of a lane is its bit z (Sec. 3.1.2, B.1).
	public static void Permute(ulong[] state)
	{
		for (int round = 0; round < Rounds; ++round)
		{
			Theta(state);
			Rho(state);
			Pi(state);
			Chi(state);
			state[0] ^= RoundConstants[round];
		}
	}

	private static void Theta(ulong[] a)
	{
		ulong[] c = new ulong[Width];

		for (int x = 0; x < Width; ++x)
		{
			c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		}

		for (int x = 0; x < Width; ++x)
		{
			ulong d = c[(x + 4) % Width] ^ BitOperations.RotateLeft(c[(x + 1) % Width], 1);

			for (int y = 0; y < Width; ++y)
			{
				a[x + Width * y] ^= d;
			}
		}
	}

	private static void Rho(ulong[] a)
	{
		for (int i = 0; i < a.Length; ++i)
		{
			a[i] = BitOperations.RotateLeft(a[i], RhoOffsets[i]);
		}
	}

	private static void Pi(ulong[] a)
	{
		ulong[] source = (ulong[])a.Clone();

		for (int x = 0; x < Width; ++x)
		{
			for (int y = 0; y < Width; ++y)
			{
				a[x + Width * y] = source[(x + 3 * y) % Width + Width * x];
			}
		}
	}

	private static void Chi(ulong[] a)
	{
		ulong[] source = (ulong[])a.Clone();

		for (int x = 0; x < Width; ++x)
		{
			for (int y = 0; y < Width; ++y)
			{
				a[x + Width * y] = source[x + Width * y] ^ ~source[(x + 1) % Width + Width * y] & source[(x + 2) % Width + Width * y];
			}
		}
	}

	private static ulong[] CreateRoundConstants()
	{
		ulong[] constants = new ulong[Rounds];

		for (int round = 0; round < Rounds; ++round)
		{
			for (int j = 0; j <= 6; ++j)
			{
				if (Rc(j + 7 * round))
				{
					constants[round] |= 1UL << (1 << j) - 1;
				}
			}
		}

		return constants;
	}

	// Algorithm 5: the output bit of an LFSR over GF(2)[x] / (x^8 + x^6 + x^5 + x^4 + 1).
	private static bool Rc(int t)
	{
		if (t % 255 is 0)
		{
			return true;
		}

		int r = 1;

		for (int i = 1; i <= t % 255; ++i)
		{
			r <<= 1;

			if ((r & 0x100) is not 0)
			{
				r ^= 0x171;
			}
		}

		return (r & 1) is not 0;
	}

	private static int[] CreateRhoOffsets()
	{
		int[] offsets = new int[Width * Width];
		int x = 1;
		int y = 0;

		for (int t = 0; t < 24; ++t)
		{
			offsets[x + Width * y] = (t + 1) * (t + 2) / 2 % LaneSize;
			(x, y) = (y, (2 * x + 3 * y) % Width);
		}

		return offsets;
	}
}
