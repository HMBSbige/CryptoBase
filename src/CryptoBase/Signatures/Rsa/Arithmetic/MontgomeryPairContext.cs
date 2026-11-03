using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Two odd moduli of one digit count that exponentiate at once with a pair kernel, which MontgomeryKernelDispatch.CreatePair takes where the platform has one and it is faster than one modulus after the other. The elements are those of the contexts of the moduli, whose kernel has the digits of the pair kernel; the moduli may be secret, and only their limb count decides the sizes. Immutable until Reset or Dispose, which erases it.
internal abstract class MontgomeryPairContext : IDisposable
{
	// firstResult = first^firstExponent and secondResult = second^secondExponent, each modulo its modulus, as MontgomeryContext.Exponentiate does for one: the time depends on the length of the exponents, which must be equal, and not on their values. A result may be its element.
	internal abstract void Exponentiate(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> firstExponent, ReadOnlySpan<ulong> second, ReadOnlySpan<ulong> secondExponent, Span<ulong> firstResult, Span<ulong> secondResult);

	// Takes the moduli of two contexts of the limb count of the constructor in place of the old ones, as a new instance would, for contexts that MontgomeryContext.Reset changed; no other method may run meanwhile.
	internal abstract void Reset(MontgomeryContext first, MontgomeryContext second);

	public abstract void Dispose();
}

internal sealed class MontgomeryPairContext<TKernel> : MontgomeryPairContext where TKernel : IMontgomeryPairKernel
{
	// The moduli as the kernel takes them, then 1 in Montgomery form for each, interleaved; pinned only for Dispose, as the data of MontgomeryContext.
	private readonly ulong[] _data;
	private readonly int _digits;
	private ulong _firstInverse;
	private ulong _secondInverse;

	internal MontgomeryPairContext(MontgomeryContext first, MontgomeryContext second)
	{
		Debug.Assert(TKernel.IsSupported && first.DigitCount >= TKernel.MinDigitCount && first.DigitCount <= TKernel.MaxDigitCount);

		_digits = first.DigitCount;
		_data = GC.AllocateUninitializedArray<ulong>(4 * _digits, true);
		Reset(first, second);
	}

	internal override void Reset(MontgomeryContext first, MontgomeryContext second)
	{
		Debug.Assert(first.LimbCount == second.LimbCount && first.DigitCount == _digits && second.DigitCount == _digits);

		int digits = _digits;
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		_firstInverse = 0 - Limbs.InvertWord(first.Modulus[0]) & mask;
		_secondInverse = 0 - Limbs.InvertWord(second.Modulus[0]) & mask;

		int bufferLength = 2 * digits;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> firstDigits = buffer.Span.Slice(0, digits);
		Span<ulong> secondDigits = buffer.Span.Slice(digits, digits);
		first.ToDigits(first.Modulus, firstDigits);
		second.ToDigits(second.Modulus, secondDigits);
		TKernel.Prepare(firstDigits, secondDigits, Moduli);
		first.WriteOne(firstDigits);
		second.WriteOne(secondDigits);
		Interleave(firstDigits, secondDigits, One);
	}

	private Span<ulong> Moduli => _data.AsSpan(0, 2 * _digits);

	private Span<ulong> One => _data.AsSpan(2 * _digits, 2 * _digits);

	internal override void Exponentiate(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> firstExponent, ReadOnlySpan<ulong> second, ReadOnlySpan<ulong> secondExponent, Span<ulong> firstResult, Span<ulong> secondResult)
	{
		int digits = _digits;

		Debug.Assert(first.Length == digits && second.Length == digits && firstResult.Length == digits && secondResult.Length == digits && firstExponent.Length == secondExponent.Length && !firstExponent.IsEmpty);

		int words = 2 * digits;
		int bits = 64 * firstExponent.Length;
		int window = MontgomeryContext.GetWindowBits(bits);
		int count = 1 << window;
		int bufferLength = (count + 2) * words + TKernel.GetScratchLength(digits);
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> table = buffer.Span.Slice(0, count * words);
		Span<ulong> accumulator = buffer.Span.Slice(count * words, words);
		Span<ulong> entry = buffer.Span.Slice((count + 1) * words, words);
		Span<ulong> scratch = buffer.Span.Slice((count + 2) * words);
		ReadOnlySpan<ulong> moduli = Moduli;
		ulong firstInverse = _firstInverse;
		ulong secondInverse = _secondInverse;

		// table[i] = the pair of element^i, as MontgomeryContext.Exponentiate builds it.
		One.CopyTo(table);
		Span<ulong> element = table.Slice(words, words);
		Interleave(first, second, element);

		for (int i = 2; i < count; ++i)
		{
			Span<ulong> power = table.Slice(i * words, words);

			if ((i & 1) is 0)
			{
				TKernel.Square(power, table.Slice(i / 2 * words, words), moduli, firstInverse, secondInverse, scratch);
			}
			else
			{
				TKernel.Multiply(power, table.Slice((i - 1) * words, words), element, moduli, firstInverse, secondInverse, scratch);
			}
		}

		// The windows of MontgomeryContext.Exponentiate, from the same positions in both exponents.
		int position = bits - (bits % window is 0 ? window : bits % window);
		Lookup(table, count, ReadWindow(firstExponent, position, bits - position), ReadWindow(secondExponent, position, bits - position), accumulator);

		while (position > 0)
		{
			position -= window;

			for (int i = 0; i < window; ++i)
			{
				TKernel.Square(accumulator, accumulator, moduli, firstInverse, secondInverse, scratch);
			}

			Lookup(table, count, ReadWindow(firstExponent, position, window), ReadWindow(secondExponent, position, window), entry);
			TKernel.Multiply(accumulator, accumulator, entry, moduli, firstInverse, secondInverse, scratch);
		}

		for (int i = 0; i < digits; ++i)
		{
			firstResult[i] = accumulator[2 * i];
			secondResult[i] = accumulator[2 * i + 1];
		}
	}

	public override void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_data.AsSpan()));
		_firstInverse = 0;
		_secondInverse = 0;
	}

	private static void Interleave(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> pair)
	{
		for (int i = 0; i < first.Length; ++i)
		{
			pair[2 * i] = first[i];
			pair[2 * i + 1] = second[i];
		}
	}

	private static ulong ReadWindow(ReadOnlySpan<ulong> exponent, int position, int bits)
	{
		return LimbArithmetic.ReadBits(exponent, position) & (1UL << bits) - 1;
	}

	private static void Lookup(ReadOnlySpan<ulong> table, int count, ulong first, ulong second, Span<ulong> entry)
	{
		MaskedSelect.LookupPair(in MemoryMarshal.GetReference(table), entry.Length, count, (uint)first, (uint)second, ref MemoryMarshal.GetReference(entry));
	}
}
