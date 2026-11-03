using CryptoBase.Signatures.Rsa.Arithmetic;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// A kernel under test with a digit size, which MontgomeryContext pairs with a modulus.
public abstract class MontgomeryKernelCase : IKernelCase
{
	private static readonly MontgomeryKernelCase[] Cases = [.. Create()];

	public static IEnumerable<MontgomeryKernelCase> All()
	{
		return Cases;
	}

	// The families, each in the order in which MontgomeryKernelDispatch tries its kernels, and in which IsDispatched looks for the first that holds a modulus.
	private static IEnumerable<MontgomeryKernelCase> Create()
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

	// The kernel of a context.
	internal static MontgomeryKernelCase Of(MontgomeryContext context)
	{
		Type kernelType = context.GetType().GetGenericArguments()[0];
		return Cases.Single(kernel => kernel.KernelType == kernelType);
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

	// The limb counts that the tests take for the kernel: those of one to three limbs that it holds, the ends of the range of limb counts up to 256 for which MontgomeryKernelDispatch takes it, and the RSA sizes of CommonLimbCounts within the range. MontgomeryKernelAdvSimd<Radix28> also takes the limb counts of MontgomeryKernelDispatch.CreatePair, from MinAdvSimdPairLimbs, below those that Create gives it, to MaxAdvSimdPairLimbs.
	internal int[] LimbCountsToTest => field ??= GetLimbCountsToTest();

	public abstract bool IsSupported { get; }

	internal abstract int DigitBits { get; }

	internal abstract int MaxDigitCount { get; }

	internal abstract int GetDigitCount(int limbs);

	// Whether a modulus of limbs limbs needs no more digits than the kernel holds.
	internal bool Fits(int limbs)
	{
		return GetDigitCount(limbs) <= MaxDigitCount;
	}

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

	private int[] GetLimbCountsToTest()
	{
		int[] dispatched = [.. Enumerable.Range(1, 256).Where(IsDispatched)];
		IEnumerable<int> limbCounts = dispatched is [] ? [] : [dispatched[0], dispatched[^1], .. RsaArithmeticTestUtils.CommonLimbCounts.Intersect(dispatched)];

		if (KernelType == typeof(MontgomeryKernelAdvSimd<Radix28>))
		{
			limbCounts = limbCounts.Append(MontgomeryKernelDispatch.MinAdvSimdPairLimbs).Append(MontgomeryKernelDispatch.MaxAdvSimdPairLimbs);
		}

		return [.. limbCounts.Concat(Enumerable.Range(1, 3).Where(Fits)).Distinct().Order()];
	}

	// Whether MontgomeryKernelDispatch takes the kernel for a modulus of limbs limbs where it takes the family: the first kernel of the family in Cases that holds the modulus, with the windows of MontgomeryKernelAvx512 and MontgomeryKernelAvx512Staged as one family, or the window of MontgomeryKernelAvx2 that GetAvx2WindowVectors gives. Of MontgomeryKernel64ColumnPairs, it takes only the 57-bit digits.
	private bool IsDispatched(int limbs)
	{
		if (!Fits(limbs))
		{
			return false;
		}

		Type family = Family(KernelType);

		if (family == typeof(MontgomeryKernelAvx2<>))
		{
			return WindowVectors(KernelType) == MontgomeryKernelDispatch.GetAvx2WindowVectors(GetDigitCount(limbs));
		}

		if (family == typeof(MontgomeryKernel64ColumnPairs<>) && KernelType != typeof(MontgomeryKernel64ColumnPairs<Radix57>))
		{
			return false;
		}

		return Cases.TakeWhile(kernel => kernel != this).All(kernel => Family(kernel.KernelType) != family || !kernel.Fits(limbs));
	}

	private static Type Family(Type kernelType)
	{
		Type family = kernelType.GetGenericTypeDefinition();
		return family == typeof(MontgomeryKernelAvx512Staged<>) ? typeof(MontgomeryKernelAvx512<>) : family;
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

		internal override int GetDigitCount(int limbs)
		{
			return MontgomeryContext<TKernel>.GetDigitCount(limbs);
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
