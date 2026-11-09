using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// The dispatch picks one single-state kernel from the CPU model, so on any one runner the other goes untested; these tests call each kernel directly wherever it is supported and check it against the reference.
public class KeccakP1600SingleStateTest
{
	public static IEnumerable<int> Rates => [72, 104, 136, 144, 168];

	public static IEnumerable<SingleStateKernel> Kernels => [new Lane128Kernel(), new Avx512Kernel()];

	public static IEnumerable<(SingleStateKernel Kernel, int Rate)> KernelsAndRates()
	{
		return Kernels.SelectMany(static kernel => Rates.Select(rate => (kernel, rate)));
	}

	[Test]
	[MethodDataSource(nameof(Kernels))]
	public async Task PermuteMatchesKeccakTeamValues(SingleStateKernel kernel)
	{
		SkipUnlessSupported(kernel);
		InlineArray25<ulong> state = default;

		kernel.Permute(ref state);
		await Assert.That(Sha3TestUtils.ToArray(state)).IsEquivalentTo(Sha3PermutationTest.ZeroStatePermutedOnce, CollectionOrdering.Matching);

		kernel.Permute(ref state);
		await Assert.That(Sha3TestUtils.ToArray(state)).IsEquivalentTo(Sha3PermutationTest.ZeroStatePermutedTwice, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(nameof(Kernels))]
	public async Task PermuteMatchesReference(SingleStateKernel kernel)
	{
		SkipUnlessSupported(kernel);

		for (int seed = 1; seed <= 3; ++seed)
		{
			InlineArray25<ulong> state = Sha3TestUtils.RandomState(seed);
			ulong[] expected = Sha3TestUtils.ToArray(state);

			for (int i = 0; i < 4; ++i)
			{
				KeccakReference.Permute(expected);
				kernel.Permute(ref state);
				await Assert.That(Sha3TestUtils.ToArray(state)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(KernelsAndRates))]
	public Task AbsorbMatchesScalar(SingleStateKernel kernel, int rate)
	{
		SkipUnlessSupported(kernel);
		return rate switch
		{
			72 => VerifyAbsorb<KeccakRate72>(kernel),
			104 => VerifyAbsorb<KeccakRate104>(kernel),
			136 => VerifyAbsorb<KeccakRate136>(kernel),
			144 => VerifyAbsorb<KeccakRate144>(kernel),
			168 => VerifyAbsorb<KeccakRate168>(kernel),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	[Test]
	[MethodDataSource(nameof(KernelsAndRates))]
	public Task SqueezeMatchesScalar(SingleStateKernel kernel, int rate)
	{
		SkipUnlessSupported(kernel);
		return rate switch
		{
			72 => VerifySqueeze<KeccakRate72>(kernel),
			104 => VerifySqueeze<KeccakRate104>(kernel),
			136 => VerifySqueeze<KeccakRate136>(kernel),
			144 => VerifySqueeze<KeccakRate144>(kernel),
			168 => VerifySqueeze<KeccakRate168>(kernel),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task HashBlockAvx512MatchesReference(int rate)
	{
		if (!KeccakP1600.IsAvx512Supported || !Avx512BW.IsSupported)
		{
			Skip.Test("AVX-512BW is not supported here.");
		}

		return rate switch
		{
			72 => VerifyHashBlock<KeccakRate72>(),
			104 => VerifyHashBlock<KeccakRate104>(),
			136 => VerifyHashBlock<KeccakRate136>(),
			144 => VerifyHashBlock<KeccakRate144>(),
			168 => VerifyHashBlock<KeccakRate168>(),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// Three whole blocks and a partial one, which the kernel must leave alone.
	private static async Task VerifyAbsorb<TRate>(SingleStateKernel kernel) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		byte[] source = new byte[3 * rate + 5];
		new Random(rate).NextBytes(source);
		InlineArray25<ulong> state = Sha3TestUtils.RandomState(rate);
		InlineArray25<ulong> expected = state;

		int absorbed = kernel.Absorb<TRate>(ref state, source);

		for (int block = 0; block < 3; ++block)
		{
			for (int lane = 0; lane < rate / sizeof(ulong); ++lane)
			{
				expected[lane] ^= BitConverter.ToUInt64(source, block * rate + lane * sizeof(ulong));
			}

			KeccakP1600.PermuteScalar(ref expected);
		}

		using (Assert.Multiple())
		{
			await Assert.That(absorbed).IsEqualTo(3 * rate);
			await Assert.That(Sha3TestUtils.ToArray(state)).IsEquivalentTo(Sha3TestUtils.ToArray(expected), CollectionOrdering.Matching);
		}
	}

	// Three whole blocks fit, and the bytes after them must stay as they were.
	private static async Task VerifySqueeze<TRate>(SingleStateKernel kernel) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		byte[] destination = new byte[3 * rate + 5];
		destination.AsSpan().Fill(0xA5);
		byte[] expectedOutput = (byte[])destination.Clone();
		InlineArray25<ulong> state = Sha3TestUtils.RandomState(rate);
		InlineArray25<ulong> expected = state;

		int written = kernel.Squeeze<TRate>(ref state, destination);

		for (int block = 0; block < 3; ++block)
		{
			KeccakP1600.PermuteScalar(ref expected);

			for (int lane = 0; lane < rate / sizeof(ulong); ++lane)
			{
				BitConverter.TryWriteBytes(expectedOutput.AsSpan(block * rate + lane * sizeof(ulong)), expected[lane]);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(3 * rate);
			await Assert.That(destination).IsEquivalentTo(expectedOutput, CollectionOrdering.Matching);
			await Assert.That(Sha3TestUtils.ToArray(state)).IsEquivalentTo(Sha3TestUtils.ToArray(expected), CollectionOrdering.Matching);
		}
	}

	// Inputs and outputs up to the rate, both domain separators, and output written over the input, which the kernel allows.
	private static async Task VerifyHashBlock<TRate>() where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		List<string> failures = [];

		foreach (byte domainSeparator in (byte[])[KeccakReference.Sha3DomainSeparator, KeccakReference.ShakeDomainSeparator])
		{
			foreach (int sourceLength in (int[])[0, 1, 7, 8, 9, rate / 2, rate - 1])
			{
				byte[] source = CreateDeterministicSource(sourceLength);

				foreach (int outputLength in (int[])[1, 8, 31, 32, rate - 1, rate])
				{
					byte[] expected = KeccakReference.Sponge(source, rate, domainSeparator, outputLength);
					byte[] separate = new byte[outputLength];
					KeccakP1600.HashBlockAvx512<TRate>(source, separate, domainSeparator);

					byte[] shared = new byte[Math.Max(sourceLength, outputLength)];
					source.CopyTo(shared, 0);
					KeccakP1600.HashBlockAvx512<TRate>(shared.AsSpan(0, sourceLength), shared.AsSpan(0, outputLength), domainSeparator);

					if (!separate.AsSpan().SequenceEqual(expected) || !shared.AsSpan(0, outputLength).SequenceEqual(expected))
					{
						failures.Add($"0x{domainSeparator:X2}, {sourceLength} -> {outputLength}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	public abstract class SingleStateKernel : IKernelCase
	{
		public abstract bool IsSupported { get; }

		internal abstract void Permute(ref InlineArray25<ulong> state);

		internal abstract int Absorb<TRate>(ref InlineArray25<ulong> state, ReadOnlySpan<byte> source) where TRate : IKeccakRate;

		internal abstract int Squeeze<TRate>(ref InlineArray25<ulong> state, Span<byte> destination) where TRate : IKeccakRate;
	}

	private sealed class Lane128Kernel : SingleStateKernel
	{
		public override bool IsSupported => KeccakP1600Lane128.IsSupported;

		internal override void Permute(ref InlineArray25<ulong> state)
		{
			KeccakP1600.PermuteLane128(ref state);
		}

		internal override int Absorb<TRate>(ref InlineArray25<ulong> state, ReadOnlySpan<byte> source)
		{
			return KeccakP1600.PermuteBlocksLane128<KeccakP1600AbsorbBlocks<TRate>>(ref state, ref MemoryMarshal.GetReference(source), source.Length);
		}

		internal override int Squeeze<TRate>(ref InlineArray25<ulong> state, Span<byte> destination)
		{
			return KeccakP1600.PermuteBlocksLane128<KeccakP1600SqueezeBlocks<TRate>>(ref state, ref MemoryMarshal.GetReference(destination), destination.Length);
		}

		public override string ToString()
		{
			return "Lane128";
		}
	}

	private sealed class Avx512Kernel : SingleStateKernel
	{
		public override bool IsSupported => KeccakP1600.IsAvx512Supported;

		internal override void Permute(ref InlineArray25<ulong> state)
		{
			KeccakP1600.PermuteAvx512(ref state);
		}

		internal override int Absorb<TRate>(ref InlineArray25<ulong> state, ReadOnlySpan<byte> source)
		{
			return KeccakP1600.PermuteBlocksAvx512<KeccakP1600AbsorbBlocks<TRate>>(ref state, ref MemoryMarshal.GetReference(source), source.Length);
		}

		internal override int Squeeze<TRate>(ref InlineArray25<ulong> state, Span<byte> destination)
		{
			return KeccakP1600.PermuteBlocksAvx512<KeccakP1600SqueezeBlocks<TRate>>(ref state, ref MemoryMarshal.GetReference(destination), destination.Length);
		}

		public override string ToString()
		{
			return "Avx512";
		}
	}
}
