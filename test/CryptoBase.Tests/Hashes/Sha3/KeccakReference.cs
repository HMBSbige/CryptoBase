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

	// The suffix bits 00 of SP 800-185, Sec. 3.3, followed by the first pad10*1 bit.
	public const byte CShakeDomainSeparator = 0x04;

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

	// The functions below transcribe SP 800-185 (https://doi.org/10.6028/NIST.SP.800-185) on byte strings, building each input whole.

	// left_encode from Sec. 2.3.1: n is the least positive integer with 2^(8n) > x, and x = sum of 256^(n-i) x_i for i = 1 to n.
	public static byte[] LeftEncode(ulong x)
	{
		byte[] digits = Base256Digits(x);
		return [(byte)digits.Length, .. digits];
	}

	// right_encode from Sec. 2.3.1.
	public static byte[] RightEncode(ulong x)
	{
		byte[] digits = Base256Digits(x);
		return [.. digits, (byte)digits.Length];
	}

	// encode_string from Sec. 2.3.2, whose length prefix counts bits.
	public static byte[] EncodeString(ReadOnlySpan<byte> s)
	{
		return TestUtils.Concat(LeftEncode((ulong)s.Length * 8), s);
	}

	// bytepad from Sec. 2.3.3.
	public static byte[] BytePad(ReadOnlySpan<byte> x, int w)
	{
		byte[] z = TestUtils.Concat(LeftEncode((ulong)w), x);
		byte[] padded = new byte[(z.Length + w - 1) / w * w];
		z.CopyTo(padded, 0);
		return padded;
	}

	// cSHAKE from Sec. 3.3: SHAKE when N and S are empty, else KECCAK[c] with the suffix bits 00.
	public static byte[] CShake(ReadOnlySpan<byte> source, int rateInBytes, ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, int outputLength)
	{
		if (functionName.IsEmpty && customization.IsEmpty)
		{
			return Sponge(source, rateInBytes, ShakeDomainSeparator, outputLength);
		}

		byte[] prefix = BytePad(TestUtils.Concat(EncodeString(functionName), EncodeString(customization)), rateInBytes);
		return Sponge(TestUtils.Concat(prefix, source), rateInBytes, CShakeDomainSeparator, outputLength);
	}

	// KMAC from Sec. 4.3 and KMACXOF from Sec. 4.3.1, which encodes the output length as 0; the rate selects KMAC128 (168) or KMAC256 (136).
	public static byte[] Kmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, int rateInBytes, ReadOnlySpan<byte> customization, int outputLength, bool xof)
	{
		byte[] newX = TestUtils.Concat(BytePad(EncodeString(key), rateInBytes), source);
		newX = TestUtils.Concat(newX, RightEncode(xof ? 0 : (ulong)outputLength * 8));
		return CShake(newX, rateInBytes, "KMAC"u8, customization, outputLength);
	}

	private static byte[] Base256Digits(ulong x)
	{
		int n = 1;

		while (n < sizeof(ulong) && x >> 8 * n is not 0)
		{
			++n;
		}

		byte[] digits = new byte[n];

		for (int i = 1; i <= n; ++i)
		{
			digits[i - 1] = (byte)(x >> 8 * (n - i));
		}

		return digits;
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
