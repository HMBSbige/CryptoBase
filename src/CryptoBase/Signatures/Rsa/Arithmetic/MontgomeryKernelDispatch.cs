namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Each kernel has a representation of its own, so the choice is made once per modulus rather than per operation: the first kernel that the platform supports and whose sums hold the digits that the modulus needs, with digits as large as they can be, which makes the fewest products. A vector kernel of the platform comes first where it holds the digits (see CreateX86). With a 64 × 64 → 128-bit multiplier, MontgomeryKernel64 takes 57-bit digits up to 3520 bits, then 56, 55 and 54; without one, MontgomeryKernel32 takes 29-bit digits up to 1728 bits, then 28 and 27. The digit count follows from the limb count alone, which is all of a secret modulus that the choice reveals.
// On ARM64, MontgomeryKernel64ColumnPairs takes 57-bit digits below AdvSimdLimbs limbs, and MontgomeryKernelAdvSimd from there on, with 28-bit digits up to 3520 bits, then 27 up to 13760 bits and 26: its digits make more products, which its vector multiplications make up for, and longer tables to read for each window of an exponent, which only longer moduli make up for.
// Two moduli of one limb count that exponentiate side by side take MontgomeryPairKernelAdvSimd on ARM64 from MinAdvSimdPairLimbs to MaxAdvSimdPairLimbs limbs, where making the products of both moduli at once makes up for the 28-bit digits of MontgomeryKernelAdvSimd. Their contexts take those digits as well, as the pair kernel requires, also below AdvSimdLimbs, at some cost to the operations of one modulus alone.
internal static partial class MontgomeryKernelDispatch
{
	private const int AdvSimdLimbs = 22;
	internal const int MinAdvSimdPairLimbs = 15;
	internal const int MaxAdvSimdPairLimbs = 27;

	// A public modulus, such as n, needs no pinned context.
	internal static MontgomeryContext Create(ReadOnlySpan<ulong> modulus, bool secret = true)
	{
		if (CreateX86(modulus, secret) is { } vector)
		{
			return vector;
		}

		int limbs = modulus.Length;

		if (MontgomeryKernelAdvSimd<Radix28>.IsSupported)
		{
			return CreateArm64(modulus, secret);
		}

		if (MontgomeryKernel64<Radix57>.IsSupported)
		{
			if (Fits<MontgomeryKernel64<Radix57>>(limbs))
			{
				return new MontgomeryContext<MontgomeryKernel64<Radix57>>(modulus, secret);
			}

			if (Fits<MontgomeryKernel64<Radix56>>(limbs))
			{
				return new MontgomeryContext<MontgomeryKernel64<Radix56>>(modulus, secret);
			}

			if (Fits<MontgomeryKernel64<Radix55>>(limbs))
			{
				return new MontgomeryContext<MontgomeryKernel64<Radix55>>(modulus, secret);
			}

			return new MontgomeryContext<MontgomeryKernel64<Radix54>>(modulus, secret);
		}

		if (Fits<MontgomeryKernel32<Radix29>>(limbs))
		{
			return new MontgomeryContext<MontgomeryKernel32<Radix29>>(modulus, secret);
		}

		if (Fits<MontgomeryKernel32<Radix28>>(limbs))
		{
			return new MontgomeryContext<MontgomeryKernel32<Radix28>>(modulus, secret);
		}

		return new MontgomeryContext<MontgomeryKernel32<Radix27>>(modulus, secret);
	}

	// The contexts of two moduli that exponentiate side by side, and the pair context that exponentiates them at once where the platform has a pair kernel for them that is faster than one after the other, which takes moduli of one limb count; null otherwise, with the contexts that Create makes. Only the limb counts decide.
	internal static MontgomeryPairContext? CreatePair(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, out MontgomeryContext firstContext, out MontgomeryContext secondContext)
	{
		int limbs = first.Length;

		if (limbs == second.Length && MontgomeryPairKernelAdvSimd<Radix28>.IsSupported && limbs is >= MinAdvSimdPairLimbs and <= MaxAdvSimdPairLimbs)
		{
			Debug.Assert(Fits<MontgomeryKernelAdvSimd<Radix28>>(limbs));

			firstContext = new MontgomeryContext<MontgomeryKernelAdvSimd<Radix28>>(first);
			secondContext = new MontgomeryContext<MontgomeryKernelAdvSimd<Radix28>>(second);
			return new MontgomeryPairContext<MontgomeryPairKernelAdvSimd<Radix28>>(firstContext, secondContext);
		}

		firstContext = Create(first);
		secondContext = Create(second);
		return limbs == second.Length ? CreatePairX86(firstContext, secondContext) : null;
	}

	private static MontgomeryContext CreateArm64(ReadOnlySpan<ulong> modulus, bool secret)
	{
		int limbs = modulus.Length;

		if (limbs < AdvSimdLimbs)
		{
			return new MontgomeryContext<MontgomeryKernel64ColumnPairs<Radix57>>(modulus, secret);
		}

		if (Fits<MontgomeryKernelAdvSimd<Radix28>>(limbs))
		{
			return new MontgomeryContext<MontgomeryKernelAdvSimd<Radix28>>(modulus, secret);
		}

		if (Fits<MontgomeryKernelAdvSimd<Radix27>>(limbs))
		{
			return new MontgomeryContext<MontgomeryKernelAdvSimd<Radix27>>(modulus, secret);
		}

		return new MontgomeryContext<MontgomeryKernelAdvSimd<Radix26>>(modulus, secret);
	}

	private static bool Fits<TKernel>(int limbs) where TKernel : IMontgomeryKernel
	{
		return MontgomeryContext<TKernel>.GetDigitCount(limbs) <= TKernel.MaxDigitCount;
	}
}
