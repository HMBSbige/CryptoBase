using CryptoBase.Hashes.Sha3;
using System.Runtime.InteropServices;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// Drives the internal cSHAKE sponge directly, against the SP 800-185 transcription in KeccakReference, with the prefixes that end
// around block boundaries: a prefix that fills its last block must not cost another permutation.
public class CShakeSpongeTest
{
	public static IEnumerable<int> Rates => [168, 136];

	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task MatchesReference(int rate)
	{
		return rate switch
		{
			168 => VerifyMatchesReference<KeccakRate168>(),
			136 => VerifyMatchesReference<KeccakRate136>(),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// Builds KMAC from InitializeKmac(K, S), Absorb(X) and AbsorbRightEncode(L).
	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task KmacMatchesReference(int rate)
	{
		return rate switch
		{
			168 => VerifyKmacMatchesReference<KeccakRate168>(),
			136 => VerifyKmacMatchesReference<KeccakRate136>(),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	[Test]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.Kmac))]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.KmacXof))]
	public async Task KmacMatchesNistSamples(KmacSample sample)
	{
		byte[] expected = Convert.FromHexString(sample.Output);
		byte[] customization = Encoding.ASCII.GetBytes(sample.Customization);
		byte[] actual = sample.Rate is 168
			? Kmac<KeccakRate168>(sample.Key, sample.Data, customization, expected.Length, sample.Xof)
			: Kmac<KeccakRate136>(sample.Key, sample.Data, customization, expected.Length, sample.Xof);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task ZeroMemoryErasesSeedAndState()
	{
		CShakeSponge<KeccakRate136> sponge = default;
		sponge.InitializeKmac(CreateDeterministicSource(32), "customization"u8);
		sponge.Absorb(CreateDeterministicSource(5));

		sponge.ZeroMemory();

		byte[] state = MemoryMarshal.AsBytes(new Span<CShakeSponge<KeccakRate136>>(ref sponge)).ToArray();
		await Assert.That(state).All(static value => value is 0);
	}

	// Lengths of the function name and customization string: both empty, which is SHAKE, a few short ones, and those whose prefix
	// ends one byte before, on, or one byte after the first or second block boundary. Equal lengths with unequal bytes catch a swap.
	private static IEnumerable<(int NameLength, int CustomizationLength)> NameAndCustomizationLengths(int rate)
	{
		yield return (0, 0);
		yield return (0, 1);
		yield return (1, 0);
		yield return (5, 5);
		yield return (4, 15);

		foreach (int target in (int[])[rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 2 * rate + 1])
		{
			yield return (0, LengthGivingPrefix(target, s => PrefixLength(rate, 0, s)));
			yield return (LengthGivingPrefix(target, n => PrefixLength(rate, n, 0)), 0);
			yield return (4, LengthGivingPrefix(target, s => PrefixLength(rate, 4, s)));
		}
	}

	// bytepad(encode_string(N) || encode_string(S), rate) before its zero padding.
	private static int PrefixLength(int rate, int nameLength, int customizationLength)
	{
		return KeccakReference.LeftEncode((ulong)rate).Length
			+ KeccakReference.EncodeString(new byte[nameLength]).Length
			+ KeccakReference.EncodeString(new byte[customizationLength]).Length;
	}

	private static int LengthGivingPrefix(int target, Func<int, int> prefixLength)
	{
		for (int length = 0; length <= target; ++length)
		{
			if (prefixLength(length) == target)
			{
				return length;
			}
		}

		throw new InvalidOperationException($"No length gives a {target}-byte prefix.");
	}

	private static IEnumerable<int> OutputLengths(int rate)
	{
		return [0, 1, rate - 1, rate, rate + 1, 3 * rate + 11];
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

	private static async Task VerifyMatchesReference<TRate>() where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		int longest = OutputLengths(rate).Max();

		foreach ((int nameLength, int customizationLength) in NameAndCustomizationLengths(rate))
		{
			byte[] name = CreateDeterministicSource(nameLength);
			byte[] customization = Customization(customizationLength);
			CShakeSponge<TRate> seeded = default;
			seeded.Initialize(name, customization);

			foreach (int messageLength in HashAlgorithmTestUtils.RateBlockAndPaddingLengths(rate))
			{
				byte[] message = CreateDeterministicSource(messageLength);
				byte[] expected = KeccakReference.CShake(message, rate, name, customization, longest);

				foreach (int outputLength in OutputLengths(rate))
				{
					CShakeSponge<TRate> sponge = seeded;
					sponge.Absorb(message);
					await Assert.That(sponge.IsSqueezing).IsFalse();
					sponge.Pad();
					await Assert.That(sponge.IsSqueezing).IsTrue();

					byte[] destination = new byte[outputLength + 2];
					PrepareDestination(destination);
					sponge.Squeeze(destination.AsSpan(1, outputLength));
					await AssertOutput(destination, 1, expected.AsSpan(0, outputLength).ToArray());
				}
			}
		}
	}

	private static async Task VerifyKmacMatchesReference<TRate>() where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		// bytepad(encode_string(K), rate) takes 2 + 3 + K bytes for keys of 32 bytes or more, so rate - 5 fills the block.
		int[] keyLengths = [0, 1, 32, rate - 6, rate - 5, rate - 4, 2 * rate - 5];
		byte[][] customizations = [[], "My Tagged Application"u8.ToArray()];

		foreach (int keyLength in keyLengths)
		{
			byte[] key = CreateDeterministicSource(keyLength);

			foreach (byte[] customization in customizations)
			{
				CShakeSponge<TRate> sponge = default;
				sponge.InitializeKmac(key, customization);

				// Each round starts from the seed that Reset restores, as after the previous round's output. Messages of rate - 3 to rate - 1
				// bytes leave right_encode(L), of 2 or 3 bytes, to fill the block or to run into the next one.
				foreach (int messageLength in (int[])[0, 1, rate - 3, rate - 2, rate - 1, rate, rate + 1])
				{
					byte[] message = CreateDeterministicSource(messageLength);

					foreach (int outputLength in (int[])[32, rate + 1])
					{
						foreach (bool xof in (bool[])[false, true])
						{
							sponge.Reset();
							sponge.Absorb(message);
							sponge.AbsorbRightEncode(xof ? 0 : (ulong)outputLength * 8);
							sponge.Pad();
							byte[] actual = new byte[outputLength];
							sponge.Squeeze(actual);

							byte[] expected = KeccakReference.Kmac(key, message, rate, customization, outputLength, xof);
							await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching)
								.Because($"{keyLength}-byte key, {customization.Length}-byte customization, {messageLength}-byte message, {outputLength}-byte output, xof: {xof}");
						}
					}
				}
			}
		}
	}

	private static byte[] Kmac<TRate>(byte[] key, byte[] source, byte[] customization, int outputLength, bool xof) where TRate : IKeccakRate
	{
		CShakeSponge<TRate> sponge = default;
		sponge.InitializeKmac(key, customization);
		sponge.Absorb(source);
		sponge.AbsorbRightEncode(xof ? 0 : (ulong)outputLength * 8);
		sponge.Pad();
		byte[] output = new byte[outputLength];
		sponge.Squeeze(output);
		return output;
	}
}
