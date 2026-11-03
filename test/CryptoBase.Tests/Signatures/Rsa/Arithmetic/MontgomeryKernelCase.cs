using CryptoBase.Signatures.Rsa.Arithmetic;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// A kernel under test with a digit size, which MontgomeryContext pairs with a modulus.
public abstract class MontgomeryKernelCase : IKernelCase
{
	public static IEnumerable<MontgomeryKernelCase> All()
	{
		yield return new Case<MontgomeryKernel64<Radix57>>();
		yield return new Case<MontgomeryKernel64<Radix56>>();
		yield return new Case<MontgomeryKernel64<Radix55>>();
		yield return new Case<MontgomeryKernel64<Radix54>>();
		yield return new Case<MontgomeryKernel32<Radix29>>();
		yield return new Case<MontgomeryKernel32<Radix28>>();
		yield return new Case<MontgomeryKernel32<Radix27>>();
		yield return new Case<MontgomeryKernel64ColumnPairs<Radix57>>();
		yield return new Case<MontgomeryKernel64ColumnPairs<Radix56>>();
		yield return new Case<MontgomeryKernel64ColumnPairs<Radix55>>();
		yield return new Case<MontgomeryKernel64ColumnPairs<Radix54>>();
		yield return new Case<MontgomeryKernelAdvSimd<Radix28>>();
		yield return new Case<MontgomeryKernelAdvSimd<Radix27>>();
		yield return new Case<MontgomeryKernelAdvSimd<Radix26>>();

		foreach (MontgomeryKernelCase kernel in Avx512<Avx512WindowPair<Avx512Window, Avx512Window>, Avx512WindowPair<Avx512Window, Avx512WindowPair<Avx512Window, Avx512Window>>>())
		{
			yield return kernel;
		}

		foreach (MontgomeryKernelCase kernel in Avx512Staged<Avx512StagedWindowPair<Avx512StagedWindow, Avx512StagedWindow>, Avx512StagedWindowPair<Avx512StagedWindow, Avx512StagedWindowPair<Avx512StagedWindow, Avx512StagedWindow>>>())
		{
			yield return kernel;
		}

		// The windows of one to four vectors that MontgomeryKernelDispatch builds.
		yield return new Case<MontgomeryKernelAvx2<Avx2Window>>();
		yield return new Case<MontgomeryKernelAvx2<Avx2WindowPair<Avx2Window, Avx2Window>>>();
		yield return new Case<MontgomeryKernelAvx2<Avx2WindowPair<Avx2Window, Avx2WindowPair<Avx2Window, Avx2Window>>>>();
		yield return new Case<MontgomeryKernelAvx2<Avx2WindowPair<Avx2WindowPair<Avx2Window, Avx2Window>, Avx2WindowPair<Avx2Window, Avx2Window>>>>();
	}

	// The families of vector kernels: the windows of those of AVX-512 set the digits they hold, those of MontgomeryKernelAvx2 only the vectors that stay in registers.
	public static bool IsVector(Type kernelType)
	{
		Type family = kernelType.GetGenericTypeDefinition();
		return family == typeof(MontgomeryKernelAvx512<>) || family == typeof(MontgomeryKernelAvx512Staged<>) || family == typeof(MontgomeryKernelAvx2<>);
	}

	// The vectors that the window of a kernel of MontgomeryKernelAvx2 keeps in registers.
	public static int WindowVectors(Type kernelType)
	{
		return kernelType.GetGenericArguments()[0].GetProperty("Count")?.GetValue(null) is int count ? count : throw new ArgumentException("The kernel has no window.", nameof(kernelType));
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract int DigitBits { get; }

	internal abstract int MaxDigitCount { get; }

	// Whether a modulus of limbs limbs needs no more digits than the kernel holds.
	internal abstract bool Fits(int limbs);

	internal abstract MontgomeryContext Create(ReadOnlySpan<ulong> modulus);

	internal abstract int GetScratchLength(int digitCount);

	// The kernel itself, on elements of the digits of the modulus, which it prepares, with the scratch given.
	internal abstract void Multiply(ReadOnlySpan<ulong> modulusDigits, Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> scratch);

	internal abstract void Square(ReadOnlySpan<ulong> modulusDigits, Span<ulong> result, ReadOnlySpan<ulong> value, Span<ulong> scratch);

	public override string ToString()
	{
		string family = KernelType.Name[..KernelType.Name.IndexOf('`')];

		return KernelType.GetGenericTypeDefinition() switch
		{
			{ } type when type == typeof(MontgomeryKernelAvx512<>) || type == typeof(MontgomeryKernelAvx512Staged<>) => $"{family}<{MaxDigitCount / 8} vectors>",
			{ } type when type == typeof(MontgomeryKernelAvx2<>) => $"{family}<{WindowVectors(KernelType)} vectors in registers>",
			_ => $"{family}<{KernelType.GetGenericArguments()[0].Name}>"
		};
	}

	// The windows that MontgomeryKernelDispatch builds, one to seven vectors.
	private static IEnumerable<MontgomeryKernelCase> Avx512<TWindow2, TWindow3>() where TWindow2 : struct, IAvx512Window<TWindow2> where TWindow3 : struct, IAvx512Window<TWindow3>
	{
		yield return new Case<MontgomeryKernelAvx512<Avx512Window>>();
		yield return new Case<MontgomeryKernelAvx512<TWindow2>>();
		yield return new Case<MontgomeryKernelAvx512<TWindow3>>();
		yield return new Case<MontgomeryKernelAvx512<Avx512WindowPair<TWindow2, TWindow2>>>();
		yield return new Case<MontgomeryKernelAvx512<Avx512WindowPair<TWindow2, TWindow3>>>();
		yield return new Case<MontgomeryKernelAvx512<Avx512WindowPair<TWindow3, TWindow3>>>();
		yield return new Case<MontgomeryKernelAvx512<Avx512WindowPair<TWindow3, Avx512WindowPair<TWindow2, TWindow2>>>>();
	}

	// The windows of eight to ten vectors, then of 12 to 20 by twos, that MontgomeryKernelDispatch builds.
	private static IEnumerable<MontgomeryKernelCase> Avx512Staged<TWindow2, TWindow3>() where TWindow2 : struct, IAvx512StagedWindow<TWindow2> where TWindow3 : struct, IAvx512StagedWindow<TWindow3>
	{
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow2>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow3>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow3, TWindow3>, Avx512StagedWindowPair<TWindow3, TWindow3>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow3, Avx512StagedWindowPair<TWindow2, TWindow2>>, Avx512StagedWindowPair<TWindow3, Avx512StagedWindowPair<TWindow2, TWindow2>>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow2>>, Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow2>>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow3>>, Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>>();
		yield return new Case<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow3>, Avx512StagedWindowPair<TWindow2, TWindow3>>, Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow3>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>>();
	}

	private sealed class Case<TKernel> : MontgomeryKernelCase where TKernel : IMontgomeryKernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override int DigitBits => TKernel.DigitBits;

		internal override int MaxDigitCount => TKernel.MaxDigitCount;

		internal override bool Fits(int limbs)
		{
			return MontgomeryContext<TKernel>.GetDigitCount(limbs) <= TKernel.MaxDigitCount;
		}

		internal override MontgomeryContext Create(ReadOnlySpan<ulong> modulus)
		{
			return new MontgomeryContext<TKernel>(modulus);
		}

		internal override int GetScratchLength(int digitCount)
		{
			return TKernel.GetScratchLength(digitCount);
		}

		internal override void Multiply(ReadOnlySpan<ulong> modulusDigits, Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> scratch)
		{
			ulong[] prepared = new ulong[modulusDigits.Length];
			TKernel.Prepare(modulusDigits, prepared);
			TKernel.Multiply(result, left, right, prepared, NegativeInverse(modulusDigits), scratch);
		}

		internal override void Square(ReadOnlySpan<ulong> modulusDigits, Span<ulong> result, ReadOnlySpan<ulong> value, Span<ulong> scratch)
		{
			ulong[] prepared = new ulong[modulusDigits.Length];
			TKernel.Prepare(modulusDigits, prepared);
			TKernel.Square(result, value, prepared, NegativeInverse(modulusDigits), scratch);
		}

		// −n⁻¹ mod 2^DigitBits, from the lowest digit, which n is congruent to modulo the radix.
		private static ulong NegativeInverse(ReadOnlySpan<ulong> modulusDigits)
		{
			return 0 - Limbs.InvertWord(modulusDigits[0]) & (1UL << TKernel.DigitBits) - 1;
		}
	}
}
