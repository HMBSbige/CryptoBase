using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// The platform implementations are independent oracles where they exist; .NET has no SHA3-224, and macOS lacks SHA-3 entirely, so the FIPS 202 transcription in KeccakReference stands in for them there.
internal static class Sha3TestUtils
{
	public static byte[] Hash(int hashLength, byte[] source)
	{
		return hashLength switch
		{
			32 when SHA3_256.IsSupported => SHA3_256.HashData(source),
			48 when SHA3_384.IsSupported => SHA3_384.HashData(source),
			64 when SHA3_512.IsSupported => SHA3_512.HashData(source),
			_ => KeccakReference.Sha3(source, hashLength)
		};
	}

	public static byte[] Hmac(int hashLength, byte[] key, byte[] source)
	{
		return hashLength switch
		{
			32 when HMACSHA3_256.IsSupported => HMACSHA3_256.HashData(key, source),
			48 when HMACSHA3_384.IsSupported => HMACSHA3_384.HashData(key, source),
			64 when HMACSHA3_512.IsSupported => HMACSHA3_512.HashData(key, source),
			_ => KeccakReference.HmacSha3(key, source, hashLength)
		};
	}

	public static byte[] Shake256Output(byte[] source, int outputLength)
	{
		return Shake256.IsSupported
			? Shake256.HashData(source, outputLength)
			: KeccakReference.Sponge(source, 136, KeccakReference.ShakeDomainSeparator, outputLength);
	}

	public static KeccakSponge<TRate> AbsorbAndPad<TRate>(ReadOnlySpan<byte> message, byte domainSeparator) where TRate : IKeccakRate
	{
		KeccakSponge<TRate> sponge = default;
		sponge.Absorb(message);
		sponge.Pad(domainSeparator);
		return sponge;
	}

	public static byte[] AbsorbPadAndSqueeze<TRate>(ReadOnlySpan<byte> message, byte domainSeparator, int outputLength) where TRate : IKeccakRate
	{
		KeccakSponge<TRate> sponge = AbsorbAndPad<TRate>(message, domainSeparator);
		byte[] output = new byte[outputLength];
		sponge.Squeeze(output);
		return output;
	}

	// Distinct suffixes for the seeded KeccakBatchSponge.Reset that use every byte they have.
	public static ushort[] Suffixes(int streams, int suffixLength)
	{
		int mask = suffixLength is 1 ? 0xFF : 0xFFFF;
		return [.. Enumerable.Range(0, streams).Select(j => (ushort)(0xA5C3 + j * 0x0101 & mask))];
	}

	// The input that the seeded KeccakBatchSponge.Reset absorbs for a stream: prefix ‖ suffix, the suffix suffixLength bytes little-endian.
	public static byte[] SeededInput(ReadOnlySpan<byte> prefix, ushort suffix, int suffixLength)
	{
		byte[] input = new byte[prefix.Length + suffixLength];
		prefix.CopyTo(input);
		input[prefix.Length] = (byte)suffix;

		if (suffixLength is 2)
		{
			input[prefix.Length + 1] = (byte)(suffix >> 8);
		}

		return input;
	}

	public static InlineArray25<ulong> RandomState(int seed)
	{
		Random random = new(seed);
		InlineArray25<ulong> state = default;

		for (int i = 0; i < 25; ++i)
		{
			state[i] = (ulong)random.NextInt64(long.MinValue, long.MaxValue);
		}

		return state;
	}

	public static ulong[] ToArray(in InlineArray25<ulong> state)
	{
		return ((ReadOnlySpan<ulong>)state).ToArray();
	}

	public static byte[] Customization(int length)
	{
		byte[] customization = CreateDeterministicSource(length);

		for (int i = 0; i < customization.Length; ++i)
		{
			customization[i] ^= 0xFF;
		}

		return customization;
	}

	public static int LengthGiving(int target, Func<int, int> encodedLength)
	{
		for (int length = 0; length <= target; ++length)
		{
			if (encodedLength(length) == target)
			{
				return length;
			}
		}

		throw new InvalidOperationException($"No length gives {target} encoded bytes.");
	}
}
