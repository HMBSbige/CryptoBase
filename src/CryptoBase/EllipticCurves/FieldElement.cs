using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// Always below m. Whether it is in Montgomery form is up to the caller: Multiply, Square and Invert work in that form, the encodings take and give the plain value, and the other operations work in either. No operation branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal struct FieldElement<TModulus> where TModulus : struct, IMontgomeryModulus
{
	private TModulus _limbs;

	internal static ref readonly FieldElement<TModulus> MontgomeryOne => ref FromLimbs(TModulus.MontgomeryOne);

	// The limbs must be below m.
	internal static ref readonly FieldElement<TModulus> FromLimbs(ReadOnlySpan<ulong> limbs)
	{
		Debug.Assert(limbs.Length == TModulus.LimbCount);

		return ref Unsafe.As<ulong, FieldElement<TModulus>>(ref MemoryMarshal.GetReference(limbs));
	}

	internal static ReadOnlySpan<ulong> GetLimbs(ref readonly FieldElement<TModulus> value)
	{
		return MemoryMarshal.CreateReadOnlySpan(ref Limbs(in value), TModulus.LimbCount);
	}

	[SkipLocalsInit]
	internal static void Add(in FieldElement<TModulus> left, in FieldElement<TModulus> right, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out FieldElement<TModulus> sum);
		ref ulong s = ref Limbs(ref sum);
		ulong carry = AddLimbs(ref Limbs(in left), ref Limbs(in right), ulong.MaxValue, ref s, TModulus.LimbCount);
		ReduceOnce(ref s, carry, out result);
	}

	[SkipLocalsInit]
	internal static void Subtract(in FieldElement<TModulus> left, in FieldElement<TModulus> right, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out FieldElement<TModulus> difference);
		ref ulong d = ref Limbs(ref difference);
		ulong borrow = SubtractLimbs(ref Limbs(in left), ref Limbs(in right), ref d, TModulus.LimbCount);
		Unsafe.SkipInit(out result);
		_ = AddLimbs(ref d, ref MemoryMarshal.GetReference(TModulus.Modulus), 0 - borrow, ref Limbs(ref result), TModulus.LimbCount);
	}

	internal static void Negate(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		FieldElement<TModulus> zero = default;
		Subtract(in zero, in value, out result);
	}

	// factor must be public.
	internal static void MultiplySmall(in FieldElement<TModulus> value, uint factor, out FieldElement<TModulus> result)
	{
		if (factor is 0)
		{
			result = default;
			return;
		}

		FieldElement<TModulus> addend = value;
		result = addend;

		for (int bit = 30 - BitOperations.LeadingZeroCount(factor); bit >= 0; --bit)
		{
			Add(in result, in result, out result);

			if ((factor >> bit & 1) is not 0)
			{
				Add(in result, in addend, out result);
			}
		}
	}

	internal static void Multiply(in FieldElement<TModulus> left, in FieldElement<TModulus> right, out FieldElement<TModulus> result)
	{
		Multiply(ref Limbs(in left), ref Limbs(in right), out result);
	}

	internal static void Square(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		Square(ref Limbs(in value), out result);
	}

	internal static void ToMontgomery(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		Multiply(ref Limbs(in value), ref MemoryMarshal.GetReference(TModulus.RSquared), out result);
	}

	internal static void FromMontgomery(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		FieldElement<TModulus> one = default;
		Limbs(ref one) = 1;
		Multiply(ref Limbs(in value), ref Limbs(ref one), out result);
	}

	// 0 gives 0. The chain is public, so the branches and table indices it decides say nothing about value.
	[SkipLocalsInit]
	internal static void Invert(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		ReadOnlySpan<byte> chain = TModulus.InversionChain;
		int stored = chain[0];
		Span<FieldElement<TModulus>> table = MemoryMarshal.Cast<ulong, FieldElement<TModulus>>(stackalloc ulong[(stored + 1) * TModulus.LimbCount]);
		table[0] = value;
		FieldElement<TModulus> power = value;

		for (int step = 0; 2 * step + 1 < chain.Length; ++step)
		{
			for (int i = chain[2 * step + 1]; i > 0; --i)
			{
				Square(in power, out power);
			}

			Multiply(in power, in table[chain[2 * step + 2]], out power);

			if (step < stored)
			{
				table[step + 1] = power;
			}
		}

		result = power;
	}

	internal static void ConditionalSelect(ulong mask, in FieldElement<TModulus> whenSet, in FieldElement<TModulus> whenClear, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out result);
		SelectLimbs(mask, ref Limbs(in whenSet), ref Limbs(in whenClear), ref Limbs(ref result), TModulus.LimbCount);
	}

	internal static void ConditionalSwap(ulong mask, ref FieldElement<TModulus> left, ref FieldElement<TModulus> right)
	{
		ref ulong x = ref Limbs(ref left);
		ref ulong y = ref Limbs(ref right);

		for (nint i = 0; i < TModulus.LimbCount; ++i)
		{
			ulong difference = (Unsafe.Add(ref x, i) ^ Unsafe.Add(ref y, i)) & mask;
			Unsafe.Add(ref x, i) ^= difference;
			Unsafe.Add(ref y, i) ^= difference;
		}
	}

	internal static ulong IsZero(in FieldElement<TModulus> value)
	{
		ref ulong x = ref Limbs(in value);
		ulong bits = 0;

		for (nint i = 0; i < TModulus.LimbCount; ++i)
		{
			bits |= Unsafe.Add(ref x, i);
		}

		return ZeroMask(bits);
	}

	internal static ulong AreEqual(in FieldElement<TModulus> left, in FieldElement<TModulus> right)
	{
		ref ulong x = ref Limbs(in left);
		ref ulong y = ref Limbs(in right);
		ulong difference = 0;

		for (nint i = 0; i < TModulus.LimbCount; ++i)
		{
			difference |= Unsafe.Add(ref x, i) ^ Unsafe.Add(ref y, i);
		}

		return ZeroMask(difference);
	}

	// Reads ByteLength big-endian bytes; if the value is not below m, result is 0.
	internal static bool TryImport(ReadOnlySpan<byte> source, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out FieldElement<TModulus> value);
		ref ulong v = ref Limbs(ref value);
		ReadBigEndian(source, ref v);
		ref ulong m = ref MemoryMarshal.GetReference(TModulus.Modulus);
		ulong borrow = 0;

		for (nint i = 0; i < TModulus.LimbCount; ++i)
		{
			_ = SubtractWithBorrow(Unsafe.Add(ref v, i), Unsafe.Add(ref m, i), ref borrow);
		}

		ulong valid = 0 - borrow;
		Unsafe.SkipInit(out result);
		ref ulong r = ref Limbs(ref result);

		for (nint i = 0; i < TModulus.LimbCount; ++i)
		{
			Unsafe.Add(ref r, i) = Unsafe.Add(ref v, i) & valid;
		}

		return valid is not 0;
	}

	// Returns whether the value lies in [1, m − 1]; if it does not, result is 0. Only the length decides a branch.
	internal static bool TryImportNonzero(ReadOnlySpan<byte> source, out FieldElement<TModulus> result)
	{
		if (source.Length != TModulus.ByteLength)
		{
			result = default;
			return false;
		}

		// TryImport leaves 0 for a value that is not below m, so the zero test rejects that too.
		_ = TryImport(source, out result);
		return IsZero(in result) is 0;
	}

	// Sets result to the plain value of any ByteLength big-endian bytes mod m: the value is below R, so multiplying it by R mod m reduces it.
	internal static void ImportReduced(ReadOnlySpan<byte> source, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out FieldElement<TModulus> value);
		ReadBigEndian(source, ref Limbs(ref value));
		Multiply(ref Limbs(ref value), ref MemoryMarshal.GetReference(TModulus.MontgomeryOne), out result);
	}

	internal static void Export(in FieldElement<TModulus> value, Span<byte> destination)
	{
		Debug.Assert(destination.Length == TModulus.ByteLength);

		ref ulong x = ref Limbs(in value);
		ref byte output = ref MemoryMarshal.GetReference(destination);
		ref byte end = ref Unsafe.Add(ref output, TModulus.ByteLength);
		int wholeLimbs = TModulus.ByteLength / sizeof(ulong);

		for (nint i = 0; i < wholeLimbs; ++i)
		{
			Unsafe.WriteUnaligned(ref Unsafe.Subtract(ref end, (i + 1) * sizeof(ulong)), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref x, i)));
		}

		if (wholeLimbs < TModulus.LimbCount)
		{
			ulong top = Unsafe.Add(ref x, wholeLimbs);

			for (nint i = TModulus.ByteLength % sizeof(ulong) - 1; i >= 0; --i)
			{
				Unsafe.Add(ref output, i) = (byte)top;
				top >>= 8;
			}
		}
	}

	// The limbs of value, which may be written only through a ref to a writable variable.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref ulong Limbs(ref readonly FieldElement<TModulus> value)
	{
		return ref Unsafe.As<TModulus, ulong>(ref Unsafe.AsRef(in value)._limbs);
	}

	private static void ReadBigEndian(ReadOnlySpan<byte> source, ref ulong limbs)
	{
		Debug.Assert(source.Length == TModulus.ByteLength);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref byte end = ref Unsafe.Add(ref input, TModulus.ByteLength);
		int wholeLimbs = TModulus.ByteLength / sizeof(ulong);

		for (nint i = 0; i < wholeLimbs; ++i)
		{
			Unsafe.Add(ref limbs, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Subtract(ref end, (i + 1) * sizeof(ulong))));
		}

		if (wholeLimbs < TModulus.LimbCount)
		{
			ulong top = 0;

			for (nint i = 0; i < TModulus.ByteLength % sizeof(ulong); ++i)
			{
				top = top << 8 | Unsafe.Add(ref input, i);
			}

			Unsafe.Add(ref limbs, wholeLimbs) = top;
		}
	}

	// x may be any value of LimbCount limbs if y < m: the product is then below m·R, as Reduce needs.
	[SkipLocalsInit]
	private static void Multiply(ref ulong x, ref ulong y, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out Product product);
		ref ulong t = ref Unsafe.As<Product, ulong>(ref product);
		int n = TModulus.LimbCount;
		Unsafe.Add(ref t, n) = MultiplyLimbs(ref x, y, ref t, n);
		if (n > 1) AddProductRow(ref x, ref y, ref t, 1);
		if (n > 2) AddProductRow(ref x, ref y, ref t, 2);
		if (n > 3) AddProductRow(ref x, ref y, ref t, 3);
		if (n > 4) AddProductRow(ref x, ref y, ref t, 4);
		if (n > 5) AddProductRow(ref x, ref y, ref t, 5);
		if (n > 6) AddProductRow(ref x, ref y, ref t, 6);
		if (n > 7) AddProductRow(ref x, ref y, ref t, 7);
		if (n > 8) AddProductRow(ref x, ref y, ref t, 8);
		Reduce(ref t, out result);
	}

	// The limbs of the product from i + LimbCount on are not yet set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddProductRow(ref ulong x, ref ulong y, ref ulong product, int i)
	{
		ref ulong row = ref Unsafe.Add(ref product, i);
		Unsafe.Add(ref row, TModulus.LimbCount) = MultiplyAddLimbs(ref x, Unsafe.Add(ref y, i), ref row, TModulus.LimbCount);
	}

	// x < m keeps x² below m·R, as Reduce needs.
	[SkipLocalsInit]
	private static void Square(ref ulong x, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out Product product);
		ref ulong t = ref Unsafe.As<Product, ulong>(ref product);
		int n = TModulus.LimbCount;
		t = 0;
		Unsafe.Add(ref t, n) = MultiplyLimbs(ref Unsafe.Add(ref x, 1), x, ref Unsafe.Add(ref t, 1), n - 1);
		if (n > 2) AddCrossRow(ref x, ref t, 1);
		if (n > 3) AddCrossRow(ref x, ref t, 2);
		if (n > 4) AddCrossRow(ref x, ref t, 3);
		if (n > 5) AddCrossRow(ref x, ref t, 4);
		if (n > 6) AddCrossRow(ref x, ref t, 5);
		if (n > 7) AddCrossRow(ref x, ref t, 6);
		if (n > 8) AddCrossRow(ref x, ref t, 7);
		Unsafe.Add(ref t, 2 * n - 1) = 0;
		ulong carry = 0;
		ulong shifted = 0;
		DoubleAddSquare(ref x, ref t, 0, ref carry, ref shifted);
		if (n > 1) DoubleAddSquare(ref x, ref t, 1, ref carry, ref shifted);
		if (n > 2) DoubleAddSquare(ref x, ref t, 2, ref carry, ref shifted);
		if (n > 3) DoubleAddSquare(ref x, ref t, 3, ref carry, ref shifted);
		if (n > 4) DoubleAddSquare(ref x, ref t, 4, ref carry, ref shifted);
		if (n > 5) DoubleAddSquare(ref x, ref t, 5, ref carry, ref shifted);
		if (n > 6) DoubleAddSquare(ref x, ref t, 6, ref carry, ref shifted);
		if (n > 7) DoubleAddSquare(ref x, ref t, 7, ref carry, ref shifted);
		if (n > 8) DoubleAddSquare(ref x, ref t, 8, ref carry, ref shifted);
		Reduce(ref t, out result);
	}

	// The limbs of the product from i + LimbCount on are not yet set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddCrossRow(ref ulong x, ref ulong product, int i)
	{
		int n = TModulus.LimbCount;
		Unsafe.Add(ref product, i + n) = MultiplyAddLimbs(ref Unsafe.Add(ref x, i + 1), Unsafe.Add(ref x, i), ref Unsafe.Add(ref product, 2 * i + 1), n - 1 - i);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DoubleAddSquare(ref ulong x, ref ulong product, int i, ref ulong carry, ref ulong shifted)
	{
		ulong word = Unsafe.Add(ref x, i);
		ulong high = LimbArithmetic.Multiply(word, word, out ulong low);
		ref ulong pair = ref Unsafe.Add(ref product, 2 * i);
		ulong even = pair;
		ulong odd = Unsafe.Add(ref pair, 1);
		pair = AddWithCarry(even << 1 | shifted, low, ref carry);
		Unsafe.Add(ref pair, 1) = AddWithCarry(odd << 1 | even >> 63, high, ref carry);
		shifted = odd >> 63;
	}

	// The product must be below m·R; it is overwritten.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void Reduce(ref ulong product, out FieldElement<TModulus> result)
	{
		ulong carry = TModulus.Reduce<TModulus>(ref product);
		ReduceOnce(ref Unsafe.Add(ref product, TModulus.LimbCount), carry, out result);
	}

	internal static ulong MontgomeryReduce(ref ulong product)
	{
		int n = TModulus.LimbCount;
		ulong carry = 0;
		ReduceRound(ref product, 0, ref carry);
		if (n > 1) ReduceRound(ref product, 1, ref carry);
		if (n > 2) ReduceRound(ref product, 2, ref carry);
		if (n > 3) ReduceRound(ref product, 3, ref carry);
		if (n > 4) ReduceRound(ref product, 4, ref carry);
		if (n > 5) ReduceRound(ref product, 5, ref carry);
		if (n > 6) ReduceRound(ref product, 6, ref carry);
		if (n > 7) ReduceRound(ref product, 7, ref carry);
		if (n > 8) ReduceRound(ref product, 8, ref carry);
		return carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ref ulong product, int i, ref ulong carry)
	{
		ref ulong row = ref Unsafe.Add(ref product, i);
		ulong q = row * TModulus.NegativeInverse;
		ulong high = MultiplyAddLimbs(ref MemoryMarshal.GetReference(TModulus.Modulus), q, ref row, TModulus.LimbCount);
		ref ulong next = ref Unsafe.Add(ref row, TModulus.LimbCount);
		next = AddWithCarry(next, high, ref carry);
	}

	// value = low + high·R must be below 2m.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void ReduceOnce(ref ulong low, ulong high, out FieldElement<TModulus> result)
	{
		Unsafe.SkipInit(out FieldElement<TModulus> difference);
		ref ulong d = ref Limbs(ref difference);
		ulong borrow = SubtractLimbs(ref low, ref MemoryMarshal.GetReference(TModulus.Modulus), ref d, TModulus.LimbCount);
		_ = SubtractWithBorrow(high, 0, ref borrow);
		Unsafe.SkipInit(out result);
		SelectLimbs(0 - borrow, ref low, ref d, ref Limbs(ref result), TModulus.LimbCount);
	}

	[InlineArray(2)]
	private struct Product
	{
		private TModulus _half;
	}
}
