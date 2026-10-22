using CryptoBase.Hashes.Sha3;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// The platform implementations are independent oracles where they exist; .NET has no SHA3-224, and macOS lacks SHA-3 entirely,
// so the FIPS 202 transcription in KeccakReference stands in for them there.
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

	public static bool IsKernelSupported(int lanes)
	{
		return lanes switch
		{
			1 => KeccakP1600Times1.IsSupported,
			2 => KeccakP1600Times2.IsSupported,
			4 => KeccakP1600Times4.IsSupported,
			8 => KeccakP1600Times8.IsSupported,
			_ => false
		};
	}

	public static void SkipUnlessKernelSupported(int lanes)
	{
		if (!IsKernelSupported(lanes))
		{
			Skip.Test($"{KernelName(lanes)} is not supported here.");
		}
	}

	public static string KernelName(int lanes)
	{
		return lanes switch
		{
			8 => nameof(KeccakP1600Times8),
			4 => nameof(KeccakP1600Times4),
			2 => nameof(KeccakP1600Times2),
			_ => nameof(KeccakP1600Times1)
		};
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
