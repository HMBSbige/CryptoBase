using CryptoBase.Signatures.Rsa.Arithmetic;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// A pair kernel under test, which MontgomeryPairContext pairs with two moduli, and the contexts of the moduli that MontgomeryKernelDispatch.CreatePair makes for it.
public abstract class MontgomeryPairKernelCase : IKernelCase
{
	// The kernels and windows that MontgomeryKernelDispatch.CreatePair builds.
	public static IEnumerable<MontgomeryPairKernelCase> All()
	{
		yield return new Case<MontgomeryPairKernelAdvSimd<Radix28>, MontgomeryKernelAdvSimd<Radix28>>();
		yield return new Avx512Case<MontgomeryPairKernelAvx512<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>>();
		yield return new Avx512Case<MontgomeryPairKernelAvx512<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>>>();
		yield return new Avx512Case<MontgomeryPairKernelAvx512<Avx512PairWindowPair<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>>>();
		yield return new Avx512Case<MontgomeryPairKernelAvx512<Avx512PairWindowPair<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>>>>();
		yield return new Avx512Case<MontgomeryPairKernelAvx512<Avx512PairWindowPair<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>>>>();
		yield return new Avx512Case<MontgomeryPairKernelAvx512<Avx512PairWindowPair<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>, Avx512PairWindowPair<Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>, Avx512PairWindowPair<Avx512PairWindow, Avx512PairWindow>>>>>();
		yield return new Avx2Case<MontgomeryPairKernelAvx2<Avx2PairWindow>>();
		yield return new Avx2Case<MontgomeryPairKernelAvx2<Avx2PairWindowPair<Avx2PairWindow, Avx2PairWindow>>>();
		yield return new Avx2Case<MontgomeryPairKernelAvx2<Avx2PairWindowPair<Avx2PairWindow, Avx2PairWindowPair<Avx2PairWindow, Avx2PairWindow>>>>();
		yield return new Avx2Case<MontgomeryPairKernelAvx2<Avx2PairWindowPair<Avx2PairWindowPair<Avx2PairWindow, Avx2PairWindow>, Avx2PairWindowPair<Avx2PairWindow, Avx2PairWindow>>>>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract int DigitBits { get; }

	internal abstract int MinDigitCount { get; }

	internal abstract int MaxDigitCount { get; }

	internal abstract MontgomeryPairContext Create(MontgomeryContext first, MontgomeryContext second);

	// A context with the digits of the kernel.
	internal abstract MontgomeryContext CreateSingle(ulong[] modulus);

	internal abstract int GetScratchLength(int digitCount);

	// The kernel itself, on pairs of elements of the digits of two moduli, which it prepares, with a scratch of its own or the one given.
	internal void Multiply(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
	{
		Multiply(first, second, result, left, right, new ulong[GetScratchLength(first.Length)]);
	}

	internal void Square(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> result, ReadOnlySpan<ulong> value)
	{
		Square(first, second, result, value, new ulong[GetScratchLength(first.Length)]);
	}

	internal abstract void Multiply(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> scratch);

	internal abstract void Square(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> result, ReadOnlySpan<ulong> value, Span<ulong> scratch);

	public override string ToString()
	{
		string family = KernelType.Name[..KernelType.Name.IndexOf('`')];
		return KernelType.GetGenericTypeDefinition() == typeof(MontgomeryPairKernelAvx2<>) ? $"{family}<{MontgomeryKernelCase.WindowVectors(KernelType)} vectors in registers>" : $"{family}<{MaxDigitCount} digits>";
	}

	// The kernel with the contexts of TSingle.
	private sealed class Case<TKernel, TSingle> : Case<TKernel> where TKernel : IMontgomeryPairKernel where TSingle : IMontgomeryKernel
	{
		internal override MontgomeryContext CreateSingle(ulong[] modulus)
		{
			return new MontgomeryContext<TSingle>(modulus);
		}
	}

	// With AVX-512, MontgomeryKernelDispatch.Create gives the digits of the pair kernel to every modulus that it takes.
	private sealed class Avx512Case<TKernel> : Case<TKernel> where TKernel : IMontgomeryPairKernel
	{
		internal override MontgomeryContext CreateSingle(ulong[] modulus)
		{
			return MontgomeryKernelDispatch.Create(modulus);
		}
	}

	// MontgomeryKernelDispatch.Create gives the digits of the pair kernel to every modulus without AVX-512, and the window of one vector gives them with it.
	private sealed class Avx2Case<TKernel> : Case<TKernel> where TKernel : IMontgomeryPairKernel
	{
		internal override MontgomeryContext CreateSingle(ulong[] modulus)
		{
			return MontgomeryKernelAvx512<Avx512Window>.IsSupported ? new MontgomeryContext<MontgomeryKernelAvx2<Avx2Window>>(modulus) : MontgomeryKernelDispatch.Create(modulus);
		}
	}

	private abstract class Case<TKernel> : MontgomeryPairKernelCase where TKernel : IMontgomeryPairKernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override int DigitBits => TKernel.DigitBits;

		internal override int MinDigitCount => TKernel.MinDigitCount;

		internal override int MaxDigitCount => TKernel.MaxDigitCount;

		internal override MontgomeryPairContext Create(MontgomeryContext first, MontgomeryContext second)
		{
			return new MontgomeryPairContext<TKernel>(first, second);
		}

		internal override int GetScratchLength(int digitCount)
		{
			return TKernel.GetScratchLength(digitCount);
		}

		internal override void Multiply(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> scratch)
		{
			ulong[] moduli = new ulong[2 * first.Length];
			TKernel.Prepare(first, second, moduli);
			TKernel.Multiply(result, left, right, moduli, NegativeInverse(first), NegativeInverse(second), scratch);
		}

		internal override void Square(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> result, ReadOnlySpan<ulong> value, Span<ulong> scratch)
		{
			ulong[] moduli = new ulong[2 * first.Length];
			TKernel.Prepare(first, second, moduli);
			TKernel.Square(result, value, moduli, NegativeInverse(first), NegativeInverse(second), scratch);
		}

		private static ulong NegativeInverse(ReadOnlySpan<ulong> modulusDigits)
		{
			return 0 - Limbs.InvertWord(modulusDigits[0]) & (1UL << TKernel.DigitBits) - 1;
		}
	}
}
