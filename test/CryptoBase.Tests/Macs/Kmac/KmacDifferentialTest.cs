using CryptoBase.Tests.Hashes;
using CryptoBase.Tests.Hashes.Sha3;
using static CryptoBase.Tests.TestUtils;
using PlatformKmac128 = System.Security.Cryptography.Kmac128;
using PlatformKmac256 = System.Security.Cryptography.Kmac256;
using PlatformKmacXof128 = System.Security.Cryptography.KmacXof128;
using PlatformKmacXof256 = System.Security.Cryptography.KmacXof256;

namespace CryptoBase.Tests.Macs.Kmac;

// Compares every variant with two independent oracles over the same grid: the platform's KMAC where available, and the SP 800-185
// transcription in KeccakReference everywhere. The key, customization string, message and output
// lengths are those around the block boundaries of bytepad(encode_string(K)), of the cSHAKE prefix, of the message with right_encode(L), and of
// the output.
public class KmacDifferentialTest
{
	private delegate byte[] Oracle(KmacVariant variant, byte[] key, byte[] source, byte[] customization, int outputLength);

	public static IEnumerable<(KmacVariant Variant, int KeyLength)> Cases()
	{
		foreach (KmacVariant variant in KmacVariant.All)
		{
			foreach (int keyLength in KeyLengths(variant.Rate))
			{
				yield return (variant, keyLength);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(Cases))]
	public Task MatchesPlatform(KmacVariant variant, int keyLength)
	{
		if (!IsPlatformSupported(variant))
		{
			Skip.Test($"The platform has no {variant} here.");
		}

		return VerifyGrid(variant, keyLength, Platform);
	}

	[Test]
	[MethodDataSource(nameof(Cases))]
	public Task MatchesReference(KmacVariant variant, int keyLength)
	{
		return VerifyGrid(variant, keyLength, static (variant, key, source, customization, outputLength) => variant.Reference(key, source, outputLength, customization));
	}

	// bytepad(encode_string(K), rate) takes left_encode(rate), 2 bytes, then left_encode(8 |K|), 2 bytes below 32-byte keys and 3 from there to
	// 8191 bytes, then K: rate - 5 bytes fill one block exactly. 31 and 32 cross the change in the length of left_encode(8 |K|).
	private static IEnumerable<int> KeyLengths(int rate)
	{
		int fillsBlock = LengthGiving(rate, length => KeccakReference.LeftEncode((ulong)rate).Length + KeccakReference.EncodeString(new byte[length]).Length);
		return [0, 1, 31, 32, fillsBlock - 1, fillsBlock, fillsBlock + 1, rate + 1, 2 * rate];
	}

	// bytepad(encode_string("KMAC") || encode_string(S), rate) takes 2 + 6 + 3 bytes before S from 32 bytes on, so rate - 11 bytes fill the block.
	private static IEnumerable<int> CustomizationLengths(int rate)
	{
		int fillsBlock = LengthGiving(rate, length => KeccakReference.LeftEncode((ulong)rate).Length
			+ KeccakReference.EncodeString("KMAC"u8).Length
			+ KeccakReference.EncodeString(new byte[length]).Length);
		return [0, 1, fillsBlock - 1, fillsBlock, fillsBlock + 1];
	}

	private static IEnumerable<int> OutputLengths(int rate)
	{
		return [1, 16, 32, rate - 1, rate, rate + 1, 2 * rate + 5];
	}

	private static int LengthGiving(int target, Func<int, int> encodedLength)
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

	public static IEnumerable<(KmacVariant Variant, int Length)> ThreeByteLengthCases()
	{
		foreach (KmacVariant variant in KmacVariant.All)
		{
			foreach (int length in (int[])[8191, 8192, 8193])
			{
				yield return (variant, length);
			}
		}
	}

	// From 8192 bytes, 65536 bits, the lengths of the key, the customization string and the output take three bytes to encode, one more than
	// anywhere in the grid.
	[Test]
	[MethodDataSource(nameof(ThreeByteLengthCases))]
	public async Task MatchesOraclesWithThreeByteLengths(KmacVariant variant, int length)
	{
		byte[] key = CreateDeterministicSource(length);
		byte[] customization = Customization(length);
		byte[] source = CreateDeterministicSource(variant.Rate + 1);
		byte[] expected = variant.Reference(key, source, length, customization);
		byte[] actual = variant.Compute(key, source, length, customization);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		if (IsPlatformSupported(variant))
		{
			await Assert.That(actual).IsEquivalentTo(Platform(variant, key, source, customization, length), CollectionOrdering.Matching);
		}
	}

	// Each instance serves every message and output length for its customization string, so that it also goes through the resets.
	private static async Task VerifyGrid(KmacVariant variant, int keyLength, Oracle oracle)
	{
		int rate = variant.Rate;
		byte[] key = CreateDeterministicSource(keyLength);

		foreach (int customizationLength in CustomizationLengths(rate))
		{
			byte[] customization = Customization(customizationLength);
			using KmacSubject kmac = variant.Create(key, customization);

			foreach (int sourceLength in HashAlgorithmTestUtils.RateBlockAndPaddingLengths(rate))
			{
				byte[] source = CreateDeterministicSource(sourceLength);

				foreach (int outputLength in OutputLengths(rate))
				{
					string because = $"{customizationLength}-byte customization, {sourceLength}-byte message, {outputLength}-byte output";
					byte[] expected = oracle(variant, key, source, customization, outputLength);
					byte[] oneShot = variant.Compute(key, source, outputLength, customization);
					byte[] incremental = new byte[outputLength];
					kmac.Append(source);
					kmac.GetAndReset(incremental);

					await Assert.That(oneShot).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(because);
					await Assert.That(incremental).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(because);

					if (variant.Xof)
					{
						kmac.Append(source);
						byte[] pieces = ReadInPieces(kmac, outputLength, rate);
						kmac.Reset();
						await Assert.That(pieces).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(because);
					}
				}
			}
		}
	}

	// Pieces that start and end inside, at and across block boundaries.
	private static byte[] ReadInPieces(KmacSubject xof, int outputLength, int rate)
	{
		int[] pieceLengths = [1, rate - 1, 7, rate, rate + 1];
		byte[] output = new byte[outputLength];

		for (int i = 0, offset = 0; offset < outputLength; ++i)
		{
			int length = Math.Min(pieceLengths[i % pieceLengths.Length], outputLength - offset);
			xof.Read(output.AsSpan(offset, length));
			offset += length;
		}

		return output;
	}

	private static byte[] Customization(int length)
	{
		byte[] customization = CreateDeterministicSource(length);

		for (int i = 0; i < customization.Length; ++i)
		{
			customization[i] ^= 0xFF;
		}

		return customization;
	}

	private static bool IsPlatformSupported(KmacVariant variant)
	{
		return (variant.SecurityStrength, variant.Xof) switch
		{
			(128, false) => PlatformKmac128.IsSupported,
			(256, false) => PlatformKmac256.IsSupported,
			(128, true) => PlatformKmacXof128.IsSupported,
			(256, true) => PlatformKmacXof256.IsSupported,
			_ => false
		};
	}

	private static byte[] Platform(KmacVariant variant, byte[] key, byte[] source, byte[] customization, int outputLength)
	{
		return (variant.SecurityStrength, variant.Xof) switch
		{
			(128, false) => PlatformKmac128.HashData(key, source, outputLength, customization),
			(256, false) => PlatformKmac256.HashData(key, source, outputLength, customization),
			(128, true) => PlatformKmacXof128.HashData(key, source, outputLength, customization),
			(256, true) => PlatformKmacXof256.HashData(key, source, outputLength, customization),
			_ => throw new NotSupportedException(variant.ToString())
		};
	}
}
