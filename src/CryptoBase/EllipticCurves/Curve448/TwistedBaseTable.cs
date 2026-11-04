namespace CryptoBase.EllipticCurves.Curve448;

// The signed combs of the fixed-base product on the twisted curve (Hamburg, "Fast and compact elliptic-curve cryptography", 2012). ScalarDigits.SignedComb recodes a scalar into DigitCount digits ±1, which split into CombCount combs of Teeth digits Spacing bits apart: at offset i < Spacing, comb j holds the digits at i + Spacing·(m + Teeth·j) for m < Teeth. Its entry e is Σ ε_m·2^(Spacing·(m + Teeth·j))·Base with ε_(Teeth − 1) = 1 and ε_m = 2e_m − 1 for m below, the 2^(Teeth − 1) values whose top digit is 1; the others are their negations. A product then takes Spacing − 1 doublings and DigitCount/Teeth additions, one for each comb at each offset.
// Each entry is a TwistedNielsPoint with canonical coordinates, 24 limbs that start on a 64-byte boundary.
internal static class TwistedBaseTable
{
	internal const int Teeth = 6;

	internal const int Spacing = 5;

	internal const int CombCount = 15;

	internal const int DigitCount = Teeth * Spacing * CombCount;

	internal const int CombLength = 1 << Teeth - 1;

	internal const int Length = CombCount * CombLength;

	private const int EntryLength = 24;

	private const int Alignment = 64;

	// Pinned, so that the boundary stays where Start finds it.
	private static readonly ulong[] Storage = Build();

	private static readonly int Start = AlignedStart(Storage);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly TwistedNielsPoint Comb(int comb)
	{
		return ref Unsafe.As<ulong, TwistedNielsPoint>(ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(Storage), Start + comb * CombLength * EntryLength));
	}

	// Entry index of a comb, negated where negative is set, which is 0 or ulong.MaxValue. The lookup reads every entry of the comb, so neither the time nor the addresses depend on index or negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Select(int comb, uint index, ulong negative, out TwistedNielsPoint result)
	{
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<TwistedNielsPoint, ulong>(ref result);

		if (Vector512.IsHardwareAccelerated)
		{
			SelectPacked(comb, index, negative, out Vector512<ulong> plus, out Vector512<ulong> minus, out Vector512<ulong> product);
			plus.StoreUnsafe(ref limbs);
			minus.StoreUnsafe(ref limbs, 8);
			product.StoreUnsafe(ref limbs, 16);
		}
		else if (Vector256.IsHardwareAccelerated)
		{
			SelectPacked(comb, index, negative, out Vector256<ulong> plus0, out Vector256<ulong> plus1, out Vector256<ulong> minus0, out Vector256<ulong> minus1, out Vector256<ulong> product0, out Vector256<ulong> product1);
			plus0.StoreUnsafe(ref limbs);
			plus1.StoreUnsafe(ref limbs, 4);
			minus0.StoreUnsafe(ref limbs, 8);
			minus1.StoreUnsafe(ref limbs, 12);
			product0.StoreUnsafe(ref limbs, 16);
			product1.StoreUnsafe(ref limbs, 20);
		}
		else if (Vector128.IsHardwareAccelerated)
		{
			SelectPacked(comb, index, negative, out Vector128<ulong> plus0, out Vector128<ulong> plus1, out Vector128<ulong> plus2, out Vector128<ulong> plus3, out Vector128<ulong> minus0, out Vector128<ulong> minus1, out Vector128<ulong> minus2, out Vector128<ulong> minus3, out Vector128<ulong> product0, out Vector128<ulong> product1, out Vector128<ulong> product2, out Vector128<ulong> product3);
			plus0.StoreUnsafe(ref limbs);
			plus1.StoreUnsafe(ref limbs, 2);
			plus2.StoreUnsafe(ref limbs, 4);
			plus3.StoreUnsafe(ref limbs, 6);
			minus0.StoreUnsafe(ref limbs, 8);
			minus1.StoreUnsafe(ref limbs, 10);
			minus2.StoreUnsafe(ref limbs, 12);
			minus3.StoreUnsafe(ref limbs, 14);
			product0.StoreUnsafe(ref limbs, 16);
			product1.StoreUnsafe(ref limbs, 18);
			product2.StoreUnsafe(ref limbs, 20);
			product3.StoreUnsafe(ref limbs, 22);
		}
		else
		{
			MaskedSelect.Lookup(in Comb(comb), CombLength, index, out result);
			Field448.ConditionalSwap(negative, ref result.YPlusX, ref result.YMinusX);
		}

		Field448.ConditionalNegate(negative, ref result.TwoDXY);
	}

	// Select for a vector kernel that turns the entry into lanes itself, in registers: the 56-bit limbs of y + x, y − x and 2d'xy, four to a vector, with y + x and y − x swapped where negative is set. 2d'xy keeps its sign, which the kernel negates. Every entry of the comb is read and ORed, masked by whether its position matches the index, into accumulators that start at zero, so that only the matching entry remains.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectPacked(int comb, uint index, ulong negative, out Vector256<ulong> plus0, out Vector256<ulong> plus1, out Vector256<ulong> minus0, out Vector256<ulong> minus1, out Vector256<ulong> product0, out Vector256<ulong> product1)
	{
		Debug.Assert(Vector256.IsHardwareAccelerated);

		ref ulong entry = ref Unsafe.As<TwistedNielsPoint, ulong>(ref Unsafe.AsRef(in Comb(comb)));
		Vector256<ulong> target = Vector256.Create((ulong)index);
		Vector256<ulong> position = Vector256<ulong>.Zero;
		Vector256<ulong> p0 = Vector256<ulong>.Zero;
		Vector256<ulong> p1 = Vector256<ulong>.Zero;
		Vector256<ulong> m0 = Vector256<ulong>.Zero;
		Vector256<ulong> m1 = Vector256<ulong>.Zero;
		Vector256<ulong> d0 = Vector256<ulong>.Zero;
		Vector256<ulong> d1 = Vector256<ulong>.Zero;

		for (int j = 0; j < CombLength; ++j)
		{
			Vector256<ulong> match = Vector256.Equals(position, target);
			p0 |= Vector256.LoadUnsafe(ref entry) & match;
			p1 |= Vector256.LoadUnsafe(ref entry, 4) & match;
			m0 |= Vector256.LoadUnsafe(ref entry, 8) & match;
			m1 |= Vector256.LoadUnsafe(ref entry, 12) & match;
			d0 |= Vector256.LoadUnsafe(ref entry, 16) & match;
			d1 |= Vector256.LoadUnsafe(ref entry, 20) & match;
			position += Vector256<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
		}

		Vector256<ulong> swap = Vector256.Create(negative);
		Vector256<ulong> swap0 = (p0 ^ m0) & swap;
		Vector256<ulong> swap1 = (p1 ^ m1) & swap;
		plus0 = p0 ^ swap0;
		plus1 = p1 ^ swap1;
		minus0 = m0 ^ swap0;
		minus1 = m1 ^ swap1;
		product0 = d0;
		product1 = d1;
	}

	// As above with each coordinate in one vector.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectPacked(int comb, uint index, ulong negative, out Vector512<ulong> plus, out Vector512<ulong> minus, out Vector512<ulong> product)
	{
		Debug.Assert(Vector512.IsHardwareAccelerated);

		ref ulong entry = ref Unsafe.As<TwistedNielsPoint, ulong>(ref Unsafe.AsRef(in Comb(comb)));
		Vector512<ulong> target = Vector512.Create((ulong)index);
		Vector512<ulong> position = Vector512<ulong>.Zero;
		Vector512<ulong> p = Vector512<ulong>.Zero;
		Vector512<ulong> m = Vector512<ulong>.Zero;
		Vector512<ulong> d = Vector512<ulong>.Zero;

		for (int j = 0; j < CombLength; ++j)
		{
			Vector512<ulong> match = Vector512.Equals(position, target);
			p |= Vector512.LoadUnsafe(ref entry) & match;
			m |= Vector512.LoadUnsafe(ref entry, 8) & match;
			d |= Vector512.LoadUnsafe(ref entry, 16) & match;
			position += Vector512<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
		}

		Vector512<ulong> swap = (p ^ m) & Vector512.Create(negative);
		plus = p ^ swap;
		minus = m ^ swap;
		product = d;
	}

	// As above with each coordinate in four vectors of two limbs, which reads each entry once where MaskedSelect would read the comb twelve times.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectPacked(int comb, uint index, ulong negative, out Vector128<ulong> plus0, out Vector128<ulong> plus1, out Vector128<ulong> plus2, out Vector128<ulong> plus3, out Vector128<ulong> minus0, out Vector128<ulong> minus1, out Vector128<ulong> minus2, out Vector128<ulong> minus3, out Vector128<ulong> product0, out Vector128<ulong> product1, out Vector128<ulong> product2, out Vector128<ulong> product3)
	{
		Debug.Assert(Vector128.IsHardwareAccelerated);

		ref ulong entry = ref Unsafe.As<TwistedNielsPoint, ulong>(ref Unsafe.AsRef(in Comb(comb)));
		Vector128<ulong> target = Vector128.Create((ulong)index);
		Vector128<ulong> position = Vector128<ulong>.Zero;
		Vector128<ulong> p0 = Vector128<ulong>.Zero, p1 = Vector128<ulong>.Zero, p2 = Vector128<ulong>.Zero, p3 = Vector128<ulong>.Zero;
		Vector128<ulong> m0 = Vector128<ulong>.Zero, m1 = Vector128<ulong>.Zero, m2 = Vector128<ulong>.Zero, m3 = Vector128<ulong>.Zero;
		Vector128<ulong> d0 = Vector128<ulong>.Zero, d1 = Vector128<ulong>.Zero, d2 = Vector128<ulong>.Zero, d3 = Vector128<ulong>.Zero;

		for (int j = 0; j < CombLength; ++j)
		{
			Vector128<ulong> match = Vector128.Equals(position, target);
			p0 = Merge(p0, Vector128.LoadUnsafe(ref entry), match);
			p1 = Merge(p1, Vector128.LoadUnsafe(ref entry, 2), match);
			p2 = Merge(p2, Vector128.LoadUnsafe(ref entry, 4), match);
			p3 = Merge(p3, Vector128.LoadUnsafe(ref entry, 6), match);
			m0 = Merge(m0, Vector128.LoadUnsafe(ref entry, 8), match);
			m1 = Merge(m1, Vector128.LoadUnsafe(ref entry, 10), match);
			m2 = Merge(m2, Vector128.LoadUnsafe(ref entry, 12), match);
			m3 = Merge(m3, Vector128.LoadUnsafe(ref entry, 14), match);
			d0 = Merge(d0, Vector128.LoadUnsafe(ref entry, 16), match);
			d1 = Merge(d1, Vector128.LoadUnsafe(ref entry, 18), match);
			d2 = Merge(d2, Vector128.LoadUnsafe(ref entry, 20), match);
			d3 = Merge(d3, Vector128.LoadUnsafe(ref entry, 22), match);
			position += Vector128<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
		}

		Vector128<ulong> swap = Vector128.Create(negative);
		Vector128<ulong> swap0 = (p0 ^ m0) & swap;
		Vector128<ulong> swap1 = (p1 ^ m1) & swap;
		Vector128<ulong> swap2 = (p2 ^ m2) & swap;
		Vector128<ulong> swap3 = (p3 ^ m3) & swap;
		plus0 = p0 ^ swap0;
		plus1 = p1 ^ swap1;
		plus2 = p2 ^ swap2;
		plus3 = p3 ^ swap3;
		minus0 = m0 ^ swap0;
		minus1 = m1 ^ swap1;
		minus2 = m2 ^ swap2;
		minus3 = m3 ^ swap3;
		product0 = d0;
		product1 = d1;
		product2 = d2;
		product3 = d3;
	}

	// accumulator with value where mask is set. At most one entry matches and the accumulators start at zero, so an OR merges as well as a select, which ARM64 does in one instruction.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Merge(Vector128<ulong> accumulator, Vector128<ulong> value, Vector128<ulong> mask)
	{
		return AdvSimd.IsSupported ? Vector128.ConditionalSelect(mask, value, accumulator) : accumulator | value & mask;
	}

	// The teeth of each comb come from the base by Spacing doublings each. Entry 0 of a comb is its top tooth less the others, and entry e adds twice the tooth of its highest set bit to the entry without that bit.
	private static ulong[] Build()
	{
		EdwardsPoint[] points = new EdwardsPoint[Length];
		EdwardsPoint[] teeth = new EdwardsPoint[Teeth];
		TwistedCachedPoint[] twice = new TwistedCachedPoint[Teeth - 1];
		EdwardsPoint tooth = TwistedEdwards448.Base;

		for (int j = 0; j < CombCount; ++j)
		{
			for (int m = 0; m < Teeth; ++m)
			{
				teeth[m] = tooth;

				for (int k = 0; k < Spacing; ++k)
				{
					TwistedEdwards448.Double(in Edwards448.AsProjective(in tooth), out EdwardsCompletedPoint doubled);
					Edwards448.ToExtended(in doubled, out tooth);
				}
			}

			int first = j * CombLength;
			points[first] = teeth[Teeth - 1];

			for (int m = 0; m < Teeth - 1; ++m)
			{
				Edwards448.Negate(in teeth[m], out EdwardsPoint negated);
				TwistedEdwards448.ToCached(in negated, out TwistedCachedPoint cached);
				TwistedEdwards448.Add(in points[first], in cached, out EdwardsCompletedPoint sum);
				Edwards448.ToExtended(in sum, out points[first]);
				TwistedEdwards448.Double(in Edwards448.AsProjective(in teeth[m]), out EdwardsCompletedPoint doubled);
				Edwards448.ToExtended(in doubled, out EdwardsPoint doubledTooth);
				TwistedEdwards448.ToCached(in doubledTooth, out twice[m]);
			}

			for (int e = 1; e < CombLength; ++e)
			{
				int top = BitOperations.Log2((uint)e);
				TwistedEdwards448.Add(in points[first + (e ^ 1 << top)], in twice[top], out EdwardsCompletedPoint sum);
				Edwards448.ToExtended(in sum, out points[first + e]);
			}
		}

		TwistedNielsPoint[] entries = new TwistedNielsPoint[Length];
		TwistedEdwards448.ToNielsVariableTime(points, entries);
		ulong[] storage = GC.AllocateUninitializedArray<ulong>(Length * EntryLength + Alignment / sizeof(ulong) - 1, true);
		MemoryMarshal.Cast<TwistedNielsPoint, ulong>(entries).CopyTo(storage.AsSpan(AlignedStart(storage)));
		return storage;
	}

	// Array data is aligned to its 8-byte elements, so the boundary falls on a whole limb.
	private static int AlignedStart(ulong[] storage)
	{
		nint address = Marshal.UnsafeAddrOfPinnedArrayElement(storage, 0);
		return (int)(-address & Alignment - 1) / sizeof(ulong);
	}
}
