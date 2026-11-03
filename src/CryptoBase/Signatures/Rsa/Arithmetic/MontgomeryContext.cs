using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// An odd modulus n > 1 with the constants of Montgomery arithmetic in the representation of a kernel, which MontgomeryKernelDispatch picks. Values outside are limbs (see Limbs); elements are the digits of the kernel, DigitCount of them, and stand in Montgomery form for x·R⁻¹ mod n, below 2n as IMontgomeryKernel describes.
// The modulus may be secret: nothing depends on its value but the result, and only LimbCount decides the sizes. Instances are immutable until Reset or Dispose, which erases them, so that the other methods may run concurrently. Methods take inputs that do not overlap their outputs unless they say otherwise, and erase the temporary storage they use.
internal abstract class MontgomeryContext : IDisposable
{
	protected MontgomeryContext(int limbCount, int digitCount)
	{
		LimbCount = limbCount;
		DigitCount = digitCount;
	}

	internal int LimbCount { get; }

	internal int DigitCount { get; }

	// The limbs of n.
	internal abstract ReadOnlySpan<ulong> Modulus { get; }

	// Takes another modulus of LimbCount limbs in place of n, as a new instance would, for a sequence of moduli that takes no allocation for each; no other method may run meanwhile.
	internal abstract void Reset(ReadOnlySpan<ulong> modulus);

	// result = value·R mod n, for a value of any number of limbs.
	internal abstract void ToMontgomery(ReadOnlySpan<ulong> value, Span<ulong> result);

	// result = element·R⁻¹ mod n, below n, in LimbCount limbs.
	internal abstract void FromMontgomery(ReadOnlySpan<ulong> element, Span<ulong> result);

	// The digits of a value below 2^(64·LimbCount), as an element with the value itself, not in Montgomery form; Multiply by one of these leaves Montgomery form.
	internal abstract void ToDigits(ReadOnlySpan<ulong> value, Span<ulong> element);

	// The value of an element below 2n reduced below n, in LimbCount limbs, without leaving Montgomery form.
	internal abstract void FromDigits(ReadOnlySpan<ulong> element, Span<ulong> result);

	// result = left·right·R⁻¹ mod n. result may be left or right.
	internal abstract void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right);

	// result = value²·R⁻¹ mod n. result may be value.
	internal abstract void Square(Span<ulong> result, ReadOnlySpan<ulong> value);

	// The words of scratch that Square takes.
	internal abstract int ScratchLength { get; }

	// As Square, with scratch of ScratchLength words, which the caller erases, for a chain of squares that takes no buffer for each.
	internal abstract void Square(Span<ulong> result, ReadOnlySpan<ulong> value, Span<ulong> scratch);

	// result = left − right mod n, below 2n. result may be left or right.
	internal abstract void Subtract(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right);

	// Reduces an element below 2n to below n in place.
	internal abstract void Reduce(Span<ulong> element);

	// result = element^exponent for a secret exponent of any number of limbs, all of whose bits count: the time depends on the length of the exponent, not on its value. result may be element.
	internal abstract void Exponentiate(ReadOnlySpan<ulong> element, ReadOnlySpan<ulong> exponent, Span<ulong> result);

	// result = element^exponent for a public exponent, on which the time depends. result may be element.
	internal abstract void ExponentiateVariableTime(ReadOnlySpan<ulong> element, ulong exponent, Span<ulong> result);

	// 1 in Montgomery form, R mod n, below n.
	internal abstract void WriteOne(Span<ulong> element);

	// R² mod n in LimbCount limbs, the numerator that gives an inverse in Montgomery form.
	internal abstract void WriteRSquared(Span<ulong> result);

	public abstract void Dispose();

	// Window bits for an exponent of bits bits, which cost about bits/window multiplications, 2^window for the table and the reading of every entry for each window. 5 bits for the 1024-bit exponents of RSA-2048 make as many multiplications as 6 with half the table to read.
	internal static int GetWindowBits(int bits)
	{
		return bits switch
		{
			> 1024 => 6,
			> 256 => 5,
			> 80 => 4,
			> 24 => 3,
			_ => 1
		};
	}
}

internal sealed class MontgomeryContext<TKernel> : MontgomeryContext where TKernel : IMontgomeryKernel
{
	// The limbs of n, its digits, the digits that the kernel takes, R² mod n, R mod n and 2n, each below n but the last, all written by Reset. Pinned only for a secret modulus, so that the GC leaves no copy for Dispose to miss: the kernels pin what they reach through pointers themselves.
	private readonly ulong[] _data;
	private ulong _negativeInverse;

	internal MontgomeryContext(ReadOnlySpan<ulong> modulus, bool secret = true) : base(modulus.Length, GetDigitCount(modulus.Length))
	{
		Debug.Assert(TKernel.IsSupported && DigitCount <= TKernel.MaxDigitCount);

		_data = GC.AllocateUninitializedArray<ulong>(LimbCount + 5 * DigitCount, secret);
		Reset(modulus);
	}

	internal override void Reset(ReadOnlySpan<ulong> modulus)
	{
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		Debug.Assert(modulus.Length == LimbCount && modulus[^1] is not 0 && (modulus[0] & 1) is 1);

		modulus.CopyTo(_data);
		ToDigits(modulus, Digits);
		TKernel.Prepare(Digits, Prepared);
		_negativeInverse = 0 - Limbs.InvertWord(modulus[0]) & mask;

		int bufferLength = 2 * LimbCount + DigitCount;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> limbs = buffer.Span.Slice(0, LimbCount);
		Span<ulong> scratch = buffer.Span.Slice(LimbCount, LimbCount);
		Span<ulong> two = buffer.Span.Slice(2 * LimbCount, DigitCount);

		// 2^(64·(LimbCount − 1)) is below n, whose top limb is not zero; doubling it brings it to R mod n, and once more to 2·R mod n, which is 2 in Montgomery form.
		limbs.Clear();
		limbs[^1] = 1;

		for (int i = 64 * (LimbCount - 1); i < TKernel.DigitBits * DigitCount; ++i)
		{
			Double(limbs, scratch);
		}

		ToDigits(limbs, One);
		Double(limbs, scratch);
		ToDigits(limbs, two);
		// 2^(r·digitCount) = R in Montgomery form is R² mod n.
		ExponentiateVariableTime(two, (ulong)(TKernel.DigitBits * DigitCount), RSquared);
		Reduce(RSquared);

		ulong carry = 0;

		for (int i = 0; i < DigitCount; ++i)
		{
			ulong digit = 2 * Digits[i] + carry;
			Twice[i] = digit & mask;
			carry = digit >> TKernel.DigitBits;
		}
	}

	internal override ReadOnlySpan<ulong> Modulus => _data.AsSpan(0, LimbCount);

	private Span<ulong> Digits => _data.AsSpan(LimbCount, DigitCount);

	private Span<ulong> Prepared => _data.AsSpan(LimbCount + DigitCount, DigitCount);

	private Span<ulong> RSquared => _data.AsSpan(LimbCount + 2 * DigitCount, DigitCount);

	private Span<ulong> One => _data.AsSpan(LimbCount + 3 * DigitCount, DigitCount);

	private Span<ulong> Twice => _data.AsSpan(LimbCount + 4 * DigitCount, DigitCount);

	internal override int ScratchLength => TKernel.GetScratchLength(DigitCount);

	// R ≥ 4n for every n of limbCount limbs.
	internal static int GetDigitCount(int limbCount)
	{
		return (64 * limbCount + 2 + TKernel.DigitBits - 1) / TKernel.DigitBits;
	}

	internal override void ToMontgomery(ReadOnlySpan<ulong> value, Span<ulong> result)
	{
		Debug.Assert(result.Length == DigitCount);

		int digits = DigitCount;
		int chunks = Math.Max((64 * value.Length + TKernel.DigitBits * digits - 1) / (TKernel.DigitBits * digits), 1);
		int bufferLength = 2 * digits + ScratchLength;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> chunk = buffer.Span.Slice(0, digits);
		Span<ulong> term = buffer.Span.Slice(digits, digits);
		Span<ulong> scratch = buffer.Span.Slice(2 * digits);

		// value = Σ chunk_j·R^j, and Horner's rule over the chunks from the top: each chunk is below R and R² mod n below n, so that their product reduces below 2n.
		ReadChunk(value, chunks - 1, chunk);
		TKernel.Multiply(result, chunk, RSquared, Prepared, _negativeInverse, scratch);

		for (int j = chunks - 2; j >= 0; --j)
		{
			TKernel.Multiply(result, result, RSquared, Prepared, _negativeInverse, scratch);
			ReadChunk(value, j, chunk);
			TKernel.Multiply(term, chunk, RSquared, Prepared, _negativeInverse, scratch);
			Add(result, term);
		}
	}

	internal override void FromMontgomery(ReadOnlySpan<ulong> element, Span<ulong> result)
	{
		Debug.Assert(element.Length == DigitCount && result.Length == LimbCount);

		int digits = DigitCount;
		int bufferLength = 2 * digits + ScratchLength;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> one = buffer.Span.Slice(0, digits);
		Span<ulong> value = buffer.Span.Slice(digits, digits);
		one.Clear();
		one[0] = 1;
		// element·1·R⁻¹ is at most (2n + R·n)/R < n + 1.
		TKernel.Multiply(value, element, one, Prepared, _negativeInverse, buffer.Span.Slice(2 * digits));
		FromDigits(value, result);
	}

	internal override void ToDigits(ReadOnlySpan<ulong> value, Span<ulong> element)
	{
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		for (int i = 0; i < element.Length; ++i)
		{
			element[i] = LimbArithmetic.ReadBits(value, TKernel.DigitBits * i) & mask;
		}
	}

	internal override void FromDigits(ReadOnlySpan<ulong> element, Span<ulong> result)
	{
		Debug.Assert(element.Length == DigitCount && result.Length == LimbCount);

		int bufferLength = DigitCount;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> reduced = buffer.Span;
		element.CopyTo(reduced);
		Reduce(reduced);
		result.Clear();
		ulong limb = 0;
		int bits = 0;
		int index = 0;

		// Digits past the limbs are zero for a value below n.
		foreach (ulong digit in reduced)
		{
			limb |= digit << bits;
			bits += TKernel.DigitBits;

			if (bits >= 64)
			{
				if (index < result.Length)
				{
					result[index++] = limb;
				}

				bits -= 64;
				limb = digit >> TKernel.DigitBits - bits;
			}
		}

		if (index < result.Length)
		{
			result[index] = limb;
		}
	}

	internal override void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
	{
		int scratchLength = ScratchLength;
		using CryptoBuffer<ulong> scratch = CryptoBuffer<ulong>.ShouldUsePool(scratchLength) ? new CryptoBuffer<ulong>(scratchLength) : new CryptoBuffer<ulong>(stackalloc ulong[scratchLength]);
		TKernel.Multiply(result, left, right, Prepared, _negativeInverse, scratch.Span);
	}

	internal override void Square(Span<ulong> result, ReadOnlySpan<ulong> value)
	{
		int scratchLength = ScratchLength;
		using CryptoBuffer<ulong> scratch = CryptoBuffer<ulong>.ShouldUsePool(scratchLength) ? new CryptoBuffer<ulong>(scratchLength) : new CryptoBuffer<ulong>(stackalloc ulong[scratchLength]);
		TKernel.Square(result, value, Prepared, _negativeInverse, scratch.Span);
	}

	internal override void Square(Span<ulong> result, ReadOnlySpan<ulong> value, Span<ulong> scratch)
	{
		Debug.Assert(scratch.Length >= ScratchLength);

		TKernel.Square(result, value, Prepared, _negativeInverse, scratch);
	}

	internal override void Subtract(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
	{
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		Debug.Assert(result.Length == DigitCount && left.Length == DigitCount && right.Length == DigitCount);

		// left + 2n − right is in (0, 4n), which Add brings below 2n.
		long borrow = 0;

		for (int i = 0; i < DigitCount; ++i)
		{
			long digit = (long)(left[i] + Twice[i]) - (long)right[i] + borrow;
			result[i] = (ulong)digit & mask;
			borrow = digit >> TKernel.DigitBits;
		}

		ReduceTwice(result, (ulong)borrow);
	}

	internal override void Reduce(Span<ulong> element)
	{
		ConditionalSubtract(element, Digits, 0);
	}

	internal override void Exponentiate(ReadOnlySpan<ulong> element, ReadOnlySpan<ulong> exponent, Span<ulong> result)
	{
		Debug.Assert(element.Length == DigitCount && result.Length == DigitCount && !exponent.IsEmpty);

		int digits = DigitCount;
		int bits = 64 * exponent.Length;
		int window = GetWindowBits(bits);
		int count = 1 << window;
		int bufferLength = (count + 2) * digits + ScratchLength;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> table = buffer.Span.Slice(0, count * digits);
		Span<ulong> accumulator = buffer.Span.Slice(count * digits, digits);
		Span<ulong> entry = buffer.Span.Slice((count + 1) * digits, digits);
		Span<ulong> scratch = buffer.Span.Slice((count + 2) * digits);
		ReadOnlySpan<ulong> modulus = Prepared;
		ulong negativeInverse = _negativeInverse;

		// table[i] = element^i.
		One.CopyTo(table);
		element.CopyTo(table.Slice(digits));

		for (int i = 2; i < count; ++i)
		{
			Span<ulong> power = table.Slice(i * digits, digits);

			if ((i & 1) is 0)
			{
				TKernel.Square(power, table.Slice(i / 2 * digits, digits), modulus, negativeInverse, scratch);
			}
			else
			{
				TKernel.Multiply(power, table.Slice((i - 1) * digits, digits), element, modulus, negativeInverse, scratch);
			}
		}

		// Fixed windows from the top, the first of bits mod window bits or a whole window; every window costs window squarings and a multiplication by an entry that every entry is read for.
		int position = bits - (bits % window is 0 ? window : bits % window);
		Lookup(table, count, ReadWindow(exponent, position, bits - position), accumulator);

		while (position > 0)
		{
			position -= window;

			for (int i = 0; i < window; ++i)
			{
				TKernel.Square(accumulator, accumulator, modulus, negativeInverse, scratch);
			}

			Lookup(table, count, ReadWindow(exponent, position, window), entry);
			TKernel.Multiply(accumulator, accumulator, entry, modulus, negativeInverse, scratch);
		}

		accumulator.CopyTo(result);
	}

	internal override void ExponentiateVariableTime(ReadOnlySpan<ulong> element, ulong exponent, Span<ulong> result)
	{
		Debug.Assert(element.Length == DigitCount && result.Length == DigitCount);

		int digits = DigitCount;
		int bufferLength = digits + ScratchLength;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> power = buffer.Span.Slice(0, digits);
		Span<ulong> scratch = buffer.Span.Slice(digits);
		element.CopyTo(power);

		if (exponent is 0)
		{
			One.CopyTo(result);
			return;
		}

		power.CopyTo(result);

		for (int bit = 62 - BitOperations.LeadingZeroCount(exponent); bit >= 0; --bit)
		{
			TKernel.Square(result, result, Prepared, _negativeInverse, scratch);

			if ((exponent >> bit & 1) is not 0)
			{
				TKernel.Multiply(result, result, power, Prepared, _negativeInverse, scratch);
			}
		}
	}

	internal override void WriteOne(Span<ulong> element)
	{
		One.CopyTo(element);
	}

	internal override void WriteRSquared(Span<ulong> result)
	{
		FromDigits(RSquared, result);
	}

	public override void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_data.AsSpan()));
		_negativeInverse = 0;
	}

	private static ulong ReadWindow(ReadOnlySpan<ulong> exponent, int position, int bits)
	{
		return LimbArithmetic.ReadBits(exponent, position) & (1UL << bits) - 1;
	}

	private void Lookup(ReadOnlySpan<ulong> table, int count, ulong index, Span<ulong> entry)
	{
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(table), DigitCount, count, (uint)index, ref MemoryMarshal.GetReference(entry));
	}

	// The digits of chunk j of a value, zero past its end.
	private void ReadChunk(ReadOnlySpan<ulong> value, int j, Span<ulong> chunk)
	{
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		int offset = TKernel.DigitBits * DigitCount * j;

		for (int i = 0; i < chunk.Length; ++i)
		{
			chunk[i] = LimbArithmetic.ReadBits(value, offset + TKernel.DigitBits * i) & mask;
		}
	}

	// result += term for elements below 2n, then below 2n again.
	private void Add(Span<ulong> result, ReadOnlySpan<ulong> term)
	{
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		ulong carry = 0;

		for (int i = 0; i < DigitCount; ++i)
		{
			ulong digit = result[i] + term[i] + carry;
			result[i] = digit & mask;
			carry = digit >> TKernel.DigitBits;
		}

		ReduceTwice(result, carry);
	}

	// Subtracts 2n from a value below 4n, given as digits and a carry above them, if it is at least 2n.
	private void ReduceTwice(Span<ulong> value, ulong carry)
	{
		ConditionalSubtract(value, Twice, carry);
	}

	// Subtracts subtrahend from value + carry·R if that does not go below zero: a first pass finds the sign of the difference, and a second takes its digits or keeps those of value, so that no buffer holds them. Not inlined, as the loops of larger callers, such as that of the Miller-Rabin test, would spill its counters.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void ConditionalSubtract(Span<ulong> value, ReadOnlySpan<ulong> subtrahend, ulong carry)
	{
		ulong mask = (1UL << TKernel.DigitBits) - 1;
		int digits = DigitCount;
		long borrow = 0;

		for (int i = 0; i < digits; ++i)
		{
			borrow = (long)value[i] - (long)subtrahend[i] + borrow >> TKernel.DigitBits;
		}

		// The difference is negative if borrow + carry is −1.
		ulong keep = (ulong)(borrow + (long)carry >> 63);
		borrow = 0;

		for (int i = 0; i < digits; ++i)
		{
			long digit = (long)value[i] - (long)subtrahend[i] + borrow;
			borrow = digit >> TKernel.DigitBits;
			value[i] = LimbArithmetic.Select(keep, value[i], (ulong)digit & mask);
		}
	}

	// value = 2·value mod n for value below n, in limbs.
	private void Double(Span<ulong> value, Span<ulong> scratch)
	{
		ulong top = value[^1] >> 63;

		for (int i = value.Length - 1; i > 0; --i)
		{
			value[i] = value[i] << 1 | value[i - 1] >> 63;
		}

		value[0] <<= 1;
		ulong borrow = Limbs.Subtract(value, Modulus, scratch);
		Limbs.Select(0 - (top | borrow ^ 1), scratch, value, value);
	}
}
