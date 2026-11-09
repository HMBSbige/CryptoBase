namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vector kernels of x86, which take precedence over the scalar ones where they hold the digits, with the smallest window that does: MontgomeryKernelAvx512 up to 20 vectors, 160 digits of 52 bits, which moduli of up to 8256 bits take, as MontgomeryKernelAvx512Staged from eight vectors on, where the operands no longer fit the registers. Past them, and without AVX-512 for every modulus, MontgomeryKernelAvx2, with 51-bit digits, the vectors past vector 0 in the window as far as MaxAvx2WindowVectors and the rest in staging.
internal static partial class MontgomeryKernelDispatch
{
	// The most vectors of a window that CreateX86 picks.
	internal const int MaxAvx512Vectors = 20;
	internal const int MinAvx512StagedVectors = 8;

	// The most vectors that the windows of MontgomeryKernelAvx2 and MontgomeryPairKernelAvx2 keep in the sixteen registers with the rest of an iteration.
	internal const int MaxAvx2WindowVectors = 4;

	// null where no vector kernel applies.
	private static MontgomeryContext? CreateX86(ReadOnlySpan<ulong> modulus, bool secret)
	{
		if (MontgomeryKernelAvx512<Avx512Window>.IsSupported)
		{
			int vectors = (MontgomeryContext<MontgomeryKernelAvx512<Avx512Window>>.GetDigitCount(modulus.Length) + 7) / 8;

			if (vectors <= MaxAvx512Vectors)
			{
				return vectors < MinAvx512StagedVectors ? CreateAvx512<Avx512WindowPair<Avx512Window, Avx512Window>, Avx512WindowPair<Avx512Window, Avx512WindowPair<Avx512Window, Avx512Window>>>(modulus, vectors, secret) : CreateAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindow, Avx512StagedWindow>, Avx512StagedWindowPair<Avx512StagedWindow, Avx512StagedWindowPair<Avx512StagedWindow, Avx512StagedWindow>>>(modulus, vectors, secret);
			}
		}

		if (MontgomeryKernelAvx2<Avx2Window>.IsSupported && Fits<MontgomeryKernelAvx2<Avx2Window>>(modulus.Length))
		{
			return CreateAvx2(modulus, GetAvx2WindowVectors(MontgomeryContext<MontgomeryKernelAvx2<Avx2Window>>.GetDigitCount(modulus.Length)), secret);
		}

		return null;
	}

	// The window of MontgomeryKernelAvx2 for digitCount digits, of four each: every vector past vector 0 as far as MaxAvx2WindowVectors.
	internal static int GetAvx2WindowVectors(int digitCount)
	{
		return Math.Clamp((digitCount + 3) / 4 - 1, 1, MaxAvx2WindowVectors);
	}

	// The window of MontgomeryPairKernelAvx2 for digitCount digits of each modulus, of two of each per vector, likewise.
	internal static int GetAvx2PairWindowVectors(int digitCount)
	{
		return Math.Clamp((digitCount + 1) / 2 - 1, 1, MaxAvx2WindowVectors);
	}

	// The windows of MontgomeryPairKernelAvx512 that CreatePairX86 picks: up to seven vectors, 28 digits of 52 bits each, which moduli of up to 1408 bits take. Without AVX-512, MontgomeryPairKernelAvx2 takes every size from its least digits on.
	internal const int MinAvx512PairVectors = 2;
	internal const int MaxAvx512PairVectors = 7;

	// With AVX-512, every modulus that a pair takes has MontgomeryKernelAvx512 and its digits; with AVX2 alone, MontgomeryKernelAvx2 and its digits.
	private static MontgomeryPairContext? CreatePairX86(MontgomeryContext first, MontgomeryContext second)
	{
		if (MontgomeryPairKernelAvx512<Avx512PairWindow>.IsSupported)
		{
			Debug.Assert(first.DigitCount == MontgomeryContext<MontgomeryKernelAvx512<Avx512Window>>.GetDigitCount(first.LimbCount));

			int vectors = (first.DigitCount + 3) / 4;
			return vectors is >= MinAvx512PairVectors and <= MaxAvx512PairVectors ? CreatePairAvx512<Avx512WindowPair<Avx512PairWindow, Avx512PairWindow>, Avx512WindowPair<Avx512PairWindow, Avx512WindowPair<Avx512PairWindow, Avx512PairWindow>>>(first, second, vectors) : null;
		}

		if (!MontgomeryPairKernelAvx2<Avx2PairWindow>.IsSupported || !Fits<MontgomeryKernelAvx2<Avx2Window>>(first.LimbCount) || first.DigitCount < MontgomeryPairKernelAvx2<Avx2PairWindow>.MinDigitCount)
		{
			return null;
		}

		Debug.Assert(first.DigitCount == MontgomeryContext<MontgomeryKernelAvx2<Avx2Window>>.GetDigitCount(first.LimbCount));

		return GetAvx2PairWindowVectors(first.DigitCount) switch
		{
			1 => new MontgomeryPairContext<MontgomeryPairKernelAvx2<Avx2PairWindow>>(first, second),
			2 => new MontgomeryPairContext<MontgomeryPairKernelAvx2<Avx2WindowPair<Avx2PairWindow, Avx2PairWindow>>>(first, second),
			3 => new MontgomeryPairContext<MontgomeryPairKernelAvx2<Avx2WindowPair<Avx2PairWindow, Avx2WindowPair<Avx2PairWindow, Avx2PairWindow>>>>(first, second),
			_ => new MontgomeryPairContext<MontgomeryPairKernelAvx2<Avx2WindowPair<Avx2WindowPair<Avx2PairWindow, Avx2PairWindow>, Avx2WindowPair<Avx2PairWindow, Avx2PairWindow>>>>(first, second)
		};
	}

	// Windows of two to seven vectors, from those of two and three.
	private static MontgomeryPairContext CreatePairAvx512<TWindow2, TWindow3>(MontgomeryContext first, MontgomeryContext second, int vectors) where TWindow2 : struct, IAvx512Window<TWindow2> where TWindow3 : struct, IAvx512Window<TWindow3>
	{
		return vectors switch
		{
			2 => new MontgomeryPairContext<MontgomeryPairKernelAvx512<TWindow2>>(first, second),
			3 => new MontgomeryPairContext<MontgomeryPairKernelAvx512<TWindow3>>(first, second),
			4 => new MontgomeryPairContext<MontgomeryPairKernelAvx512<Avx512WindowPair<TWindow2, TWindow2>>>(first, second),
			5 => new MontgomeryPairContext<MontgomeryPairKernelAvx512<Avx512WindowPair<TWindow2, TWindow3>>>(first, second),
			6 => new MontgomeryPairContext<MontgomeryPairKernelAvx512<Avx512WindowPair<TWindow3, TWindow3>>>(first, second),
			_ => new MontgomeryPairContext<MontgomeryPairKernelAvx512<Avx512WindowPair<TWindow3, Avx512WindowPair<TWindow2, TWindow2>>>>(first, second)
		};
	}

	// Windows of one to seven vectors; MontgomeryKernelAvx512Staged takes the larger ones.
	private static MontgomeryContext CreateAvx512<TWindow2, TWindow3>(ReadOnlySpan<ulong> modulus, int vectors, bool secret) where TWindow2 : struct, IAvx512Window<TWindow2> where TWindow3 : struct, IAvx512Window<TWindow3>
	{
		return vectors switch
		{
			1 => new MontgomeryContext<MontgomeryKernelAvx512<Avx512Window>>(modulus, secret),
			2 => new MontgomeryContext<MontgomeryKernelAvx512<TWindow2>>(modulus, secret),
			3 => new MontgomeryContext<MontgomeryKernelAvx512<TWindow3>>(modulus, secret),
			4 => new MontgomeryContext<MontgomeryKernelAvx512<Avx512WindowPair<TWindow2, TWindow2>>>(modulus, secret),
			5 => new MontgomeryContext<MontgomeryKernelAvx512<Avx512WindowPair<TWindow2, TWindow3>>>(modulus, secret),
			6 => new MontgomeryContext<MontgomeryKernelAvx512<Avx512WindowPair<TWindow3, TWindow3>>>(modulus, secret),
			_ => new MontgomeryContext<MontgomeryKernelAvx512<Avx512WindowPair<TWindow3, Avx512WindowPair<TWindow2, TWindow2>>>>(modulus, secret)
		};
	}

	// Windows of eight to ten vectors, then of 12 to 20 by twos, from those of two and three.
	private static MontgomeryContext CreateAvx512Staged<TWindow2, TWindow3>(ReadOnlySpan<ulong> modulus, int vectors, bool secret) where TWindow2 : struct, IAvx512StagedWindow<TWindow2> where TWindow3 : struct, IAvx512StagedWindow<TWindow3>
	{
		return vectors switch
		{
			8 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow2>>>>(modulus, secret),
			9 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>(modulus, secret),
			10 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow3>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>(modulus, secret),
			<= 12 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow3, TWindow3>, Avx512StagedWindowPair<TWindow3, TWindow3>>>>(modulus, secret),
			<= 14 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow3, Avx512StagedWindowPair<TWindow2, TWindow2>>, Avx512StagedWindowPair<TWindow3, Avx512StagedWindowPair<TWindow2, TWindow2>>>>>(modulus, secret),
			<= 16 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow2>>, Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow2>>>>>(modulus, secret),
			<= 18 => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow3>>, Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow2>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>>(modulus, secret),
			_ => new MontgomeryContext<MontgomeryKernelAvx512Staged<Avx512StagedWindowPair<Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow3>, Avx512StagedWindowPair<TWindow2, TWindow3>>, Avx512StagedWindowPair<Avx512StagedWindowPair<TWindow2, TWindow3>, Avx512StagedWindowPair<TWindow2, TWindow3>>>>>(modulus, secret)
		};
	}

	// Windows of one to four vectors.
	private static MontgomeryContext CreateAvx2(ReadOnlySpan<ulong> modulus, int windowVectors, bool secret)
	{
		return windowVectors switch
		{
			1 => new MontgomeryContext<MontgomeryKernelAvx2<Avx2Window>>(modulus, secret),
			2 => new MontgomeryContext<MontgomeryKernelAvx2<Avx2WindowPair<Avx2Window, Avx2Window>>>(modulus, secret),
			3 => new MontgomeryContext<MontgomeryKernelAvx2<Avx2WindowPair<Avx2Window, Avx2WindowPair<Avx2Window, Avx2Window>>>>(modulus, secret),
			_ => new MontgomeryContext<MontgomeryKernelAvx2<Avx2WindowPair<Avx2WindowPair<Avx2Window, Avx2Window>, Avx2WindowPair<Avx2Window, Avx2Window>>>>(modulus, secret)
		};
	}
}
