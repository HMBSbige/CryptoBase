using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.Curve25519;

// Window i holds j·2^(wi)·B for j from 1 to 2^(w − 1), w = Width, with a window for every signed digit of a 256-bit scalar. Each entry is (y + x, y − x, 2dxy) as canonical values in four 64-bit limbs each. The entries start on a 64-byte boundary.
internal static class EdwardsBaseTable
{
	internal const int Width = 6;

	internal const int EntryLength = 12;

	private const int Alignment = 64;

	// Pinned, so that the boundary stays where Start finds it.
	private static readonly ulong[] Storage = Build();

	private static readonly int Start = AlignedStart(Storage);

	internal static int WindowCount => ScalarDigits.SignedWindowCount(Width);

	internal static int WindowLength => 1 << Width - 1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly ulong Window(int index)
	{
		return ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(Storage), Start + index * WindowLength * EntryLength);
	}

	// digit·2^(wi)·B from window i, and the identity for a digit of 0. The lookup reads every entry of the window, so neither the time nor the addresses depend on the digit.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void Select(int window, int digit, out EdwardsNielsPoint result)
	{
		int sign = digit >> 31;
		Unsafe.SkipInit(out result);
		Lookup(in Window(window), (uint)((digit ^ sign) - sign) - 1, ref Unsafe.As<EdwardsNielsPoint, ulong>(ref result));
		Unpack(ref result);
		// A digit of 0 matches no entry, which leaves (0, 0, 0).
		ulong zero = ZeroMask((uint)digit) & 1;
		result.YPlusX.L0 |= zero;
		result.YMinusX.L0 |= zero;
		ulong negative = (ulong)sign;
		Field25519.ConditionalSwap(negative, ref result.YPlusX, ref result.YMinusX);
		Field25519.ConditionalNegate(negative, ref result.TwoDXY);
	}

	// Select for a kernel that turns the entry into lanes itself, in registers: y + x, y − x and 2dxy in the four 64-bit limbs of the entry, with y + x and y − x swapped for a negative digit and (1, 1, 0) for a digit of 0. 2dxy keeps its sign, which the caller negates where digit is negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectPacked(int window, int digit, out Vector256<ulong> yPlusX, out Vector256<ulong> yMinusX, out Vector256<ulong> twoDXY)
	{
		Debug.Assert(Vector256.IsHardwareAccelerated);

		int sign = digit >> 31;
		uint index = (uint)((digit ^ sign) - sign) - 1;
		Vector256<ulong> plus;
		Vector256<ulong> minus;

		if (Vector512.IsHardwareAccelerated)
		{
			Lookup512(ref Unsafe.AsRef(in Window(window)), index, out Vector512<ulong> sums, out twoDXY);
			plus = sums.GetLower();
			minus = sums.GetUpper();
		}
		else
		{
			Lookup256(ref Unsafe.AsRef(in Window(window)), index, out plus, out minus, out twoDXY);
		}

		Vector256<ulong> one = Vector256.CreateScalar(ZeroMask((uint)digit) & 1);
		plus |= one;
		minus |= one;
		Vector256<ulong> swap = (plus ^ minus) & Vector256.Create((ulong)sign);
		yPlusX = plus ^ swap;
		yMinusX = minus ^ swap;
	}

	// As above with y + x in the low half of sums and y − x in the high half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectPacked(int window, int digit, out Vector512<ulong> sums, out Vector256<ulong> twoDXY)
	{
		Debug.Assert(Vector512.IsHardwareAccelerated);

		int sign = digit >> 31;
		Lookup512(ref Unsafe.AsRef(in Window(window)), (uint)((digit ^ sign) - sign) - 1, out Vector512<ulong> entry, out twoDXY);
		entry |= Vector512.Create(ZeroMask((uint)digit)) & Vector512.Create(1UL, 0, 0, 0, 1, 0, 0, 0);
		sums = Vector512.ConditionalSelect(Vector512.Create((ulong)sign), Avx512F.Shuffle4x128(entry, entry, 0b01_00_11_10), entry);
	}

	// As above in pairs of limbs: y + x in plus0 and plus1, y − x in minus0 and minus1, and 2dxy in product0 and product1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectPacked(int window, int digit, out Vector128<ulong> plus0, out Vector128<ulong> plus1, out Vector128<ulong> minus0, out Vector128<ulong> minus1, out Vector128<ulong> product0, out Vector128<ulong> product1)
	{
		Debug.Assert(Vector128.IsHardwareAccelerated);

		int sign = digit >> 31;
		Lookup128(ref Unsafe.AsRef(in Window(window)), (uint)((digit ^ sign) - sign) - 1, out Vector128<ulong> l0, out Vector128<ulong> l1, out Vector128<ulong> l2, out Vector128<ulong> l3, out product0, out product1);
		Vector128<ulong> one = Vector128.CreateScalar(ZeroMask((uint)digit) & 1);
		l0 |= one;
		l2 |= one;
		Vector128<ulong> negative = Vector128.Create((ulong)sign);
		Vector128<ulong> swap0 = (l0 ^ l2) & negative;
		Vector128<ulong> swap1 = (l1 ^ l3) & negative;
		plus0 = l0 ^ swap0;
		plus1 = l1 ^ swap1;
		minus0 = l2 ^ swap0;
		minus1 = l3 ^ swap1;
	}

	// index counts entries across the windows and must be public, as the address read depends on it.
	internal static void Read(int index, out EdwardsNielsPoint result)
	{
		Unsafe.SkipInit(out result);
		MemoryMarshal.CreateReadOnlySpan(in Unsafe.Add(ref Unsafe.AsRef(in Window(0)), index * EntryLength), EntryLength).CopyTo(MemoryMarshal.Cast<EdwardsNielsPoint, ulong>(new Span<EdwardsNielsPoint>(ref result)));
		Unpack(ref result);
	}

	// The twelve limbs of the entry at index of a window, or zeros for an index past it. Every limb of every entry is read and merged under a mask, 0 or all ones from the index alone, which each entry takes once for all its limbs; the masks come from comparing vectors of entry positions with the index. Only hardware-accelerated vectors are used, as the software fallback of the others may branch on the values. Each width has a method of its own, which keeps the locals of the others out of the inlinee.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Lookup(ref readonly ulong window, uint index, ref ulong result)
	{
		if (Vector512.IsHardwareAccelerated)
		{
			Lookup512(ref Unsafe.AsRef(in window), index, out Vector512<ulong> low, out Vector256<ulong> high);
			low.StoreUnsafe(ref result);
			high.StoreUnsafe(ref result, 8);
		}
		else if (Vector256.IsHardwareAccelerated)
		{
			Lookup256(ref Unsafe.AsRef(in window), index, out Vector256<ulong> low, out Vector256<ulong> middle, out Vector256<ulong> high);
			low.StoreUnsafe(ref result);
			middle.StoreUnsafe(ref result, 4);
			high.StoreUnsafe(ref result, 8);
		}
		else if (Vector128.IsHardwareAccelerated)
		{
			Lookup128(ref Unsafe.AsRef(in window), index, out Vector128<ulong> l0, out Vector128<ulong> l1, out Vector128<ulong> l2, out Vector128<ulong> l3, out Vector128<ulong> l4, out Vector128<ulong> l5);
			l0.StoreUnsafe(ref result);
			l1.StoreUnsafe(ref result, 2);
			l2.StoreUnsafe(ref result, 4);
			l3.StoreUnsafe(ref result, 6);
			l4.StoreUnsafe(ref result, 8);
			l5.StoreUnsafe(ref result, 10);
		}
		else
		{
			MaskedSelect.Lookup<LimbScalar>(in window, EntryLength, WindowLength, index, ref result);
		}
	}

	// The even and the odd entries merge into accumulators of their own, which halves the chain of merges.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Lookup512(ref ulong entry, uint index, out Vector512<ulong> low, out Vector256<ulong> high)
	{
		Vector512<ulong> target = Vector512.Create((ulong)index);
		Vector512<ulong> two = Vector512.Create(2UL);
		Vector512<ulong> evenPosition = Vector512<ulong>.Zero;
		Vector512<ulong> oddPosition = Vector512.Create(1UL);
		Vector512<ulong> lowEven = Vector512<ulong>.Zero;
		Vector512<ulong> lowOdd = Vector512<ulong>.Zero;
		Vector256<ulong> highEven = Vector256<ulong>.Zero;
		Vector256<ulong> highOdd = Vector256<ulong>.Zero;

		for (int j = 0; j < WindowLength; j += 2)
		{
			Vector512<ulong> even = Vector512.Equals(evenPosition, target);
			Vector512<ulong> odd = Vector512.Equals(oddPosition, target);
			lowEven |= Vector512.LoadUnsafe(ref entry) & even;
			highEven |= Vector256.LoadUnsafe(ref entry, 8) & even.GetLower();
			lowOdd |= Vector512.LoadUnsafe(ref entry, EntryLength) & odd;
			highOdd |= Vector256.LoadUnsafe(ref entry, EntryLength + 8) & odd.GetLower();
			evenPosition += two;
			oddPosition += two;
			entry = ref Unsafe.Add(ref entry, 2 * EntryLength);
		}

		low = lowEven | lowOdd;
		high = highEven | highOdd;
	}

	// The even and the odd entries merge into accumulators of their own, which halves the chain of merges.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Lookup256(ref ulong entry, uint index, out Vector256<ulong> low, out Vector256<ulong> middle, out Vector256<ulong> high)
	{
		Vector256<ulong> target = Vector256.Create((ulong)index);
		Vector256<ulong> two = Vector256.Create(2UL);
		Vector256<ulong> evenPosition = Vector256<ulong>.Zero;
		Vector256<ulong> oddPosition = Vector256.Create(1UL);
		Vector256<ulong> evenLow = Vector256<ulong>.Zero;
		Vector256<ulong> evenMiddle = Vector256<ulong>.Zero;
		Vector256<ulong> evenHigh = Vector256<ulong>.Zero;
		Vector256<ulong> oddLow = Vector256<ulong>.Zero;
		Vector256<ulong> oddMiddle = Vector256<ulong>.Zero;
		Vector256<ulong> oddHigh = Vector256<ulong>.Zero;

		for (int j = 0; j < WindowLength; j += 2)
		{
			Vector256<ulong> even = Vector256.Equals(evenPosition, target);
			Vector256<ulong> odd = Vector256.Equals(oddPosition, target);
			evenPosition += two;
			oddPosition += two;
			evenLow |= Vector256.LoadUnsafe(ref entry) & even;
			evenMiddle |= Vector256.LoadUnsafe(ref entry, 4) & even;
			evenHigh |= Vector256.LoadUnsafe(ref entry, 8) & even;
			oddLow |= Vector256.LoadUnsafe(ref entry, EntryLength) & odd;
			oddMiddle |= Vector256.LoadUnsafe(ref entry, EntryLength + 4) & odd;
			oddHigh |= Vector256.LoadUnsafe(ref entry, EntryLength + 8) & odd;
			entry = ref Unsafe.Add(ref entry, 2 * EntryLength);
		}

		low = evenLow | oddLow;
		middle = evenMiddle | oddMiddle;
		high = evenHigh | oddHigh;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Lookup128(ref ulong entry, uint index, out Vector128<ulong> l0, out Vector128<ulong> l1, out Vector128<ulong> l2, out Vector128<ulong> l3, out Vector128<ulong> l4, out Vector128<ulong> l5)
	{
		Vector128<ulong> target = Vector128.Create((ulong)index);
		Vector128<ulong> position = Vector128<ulong>.Zero;
		l0 = Vector128<ulong>.Zero;
		l1 = Vector128<ulong>.Zero;
		l2 = Vector128<ulong>.Zero;
		l3 = Vector128<ulong>.Zero;
		l4 = Vector128<ulong>.Zero;
		l5 = Vector128<ulong>.Zero;

		for (int j = 0; j < WindowLength; ++j)
		{
			Vector128<ulong> mask = Vector128.Equals(position, target);
			l0 = Merge(l0, Vector128.LoadUnsafe(ref entry), mask);
			l1 = Merge(l1, Vector128.LoadUnsafe(ref entry, 2), mask);
			l2 = Merge(l2, Vector128.LoadUnsafe(ref entry, 4), mask);
			l3 = Merge(l3, Vector128.LoadUnsafe(ref entry, 6), mask);
			l4 = Merge(l4, Vector128.LoadUnsafe(ref entry, 8), mask);
			l5 = Merge(l5, Vector128.LoadUnsafe(ref entry, 10), mask);
			position += Vector128<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
		}
	}

	// accumulator with value where mask is set. The accumulators start at zero and at most one entry of a window matches, so an OR merges as well as a select: ARM64 takes the select, one instruction there, and x64 the AND and the OR, where the select takes three.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Merge(Vector128<ulong> accumulator, Vector128<ulong> value, Vector128<ulong> mask)
	{
		return AdvSimd.IsSupported ? Vector128.ConditionalSelect(mask, value, accumulator) : accumulator | value & mask;
	}

	// Turns the packed limbs at the start of point into its coordinates in place; the coordinates overlap the limbs, so all twelve are read first.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Unpack(ref EdwardsNielsPoint point)
	{
		ref ulong limbs = ref Unsafe.As<EdwardsNielsPoint, ulong>(ref point);
		ulong w0 = limbs;
		ulong w1 = Unsafe.Add(ref limbs, 1);
		ulong w2 = Unsafe.Add(ref limbs, 2);
		ulong w3 = Unsafe.Add(ref limbs, 3);
		ulong w4 = Unsafe.Add(ref limbs, 4);
		ulong w5 = Unsafe.Add(ref limbs, 5);
		ulong w6 = Unsafe.Add(ref limbs, 6);
		ulong w7 = Unsafe.Add(ref limbs, 7);
		ulong w8 = Unsafe.Add(ref limbs, 8);
		ulong w9 = Unsafe.Add(ref limbs, 9);
		ulong w10 = Unsafe.Add(ref limbs, 10);
		ulong w11 = Unsafe.Add(ref limbs, 11);
		Field25519.FromLimbs(w0, w1, w2, w3, out point.YPlusX);
		Field25519.FromLimbs(w4, w5, w6, w7, out point.YMinusX);
		Field25519.FromLimbs(w8, w9, w10, w11, out point.TwoDXY);
	}

	// The base of a window doubles into its second entry, and each later entry adds the base.
	private static ulong[] Build()
	{
		Debug.Assert(WindowLength >= 2);

		EdwardsPoint[] multiples = new EdwardsPoint[WindowCount * WindowLength];
		EdwardsPoint windowBase = Edwards25519.Base;

		for (int i = 0; i < multiples.Length; i += WindowLength)
		{
			multiples[i] = windowBase;
			Edwards25519.Double(in windowBase, out multiples[i + 1]);
			Edwards25519.ToCached(in windowBase, out EdwardsCachedPoint cached);

			for (int j = 2; j < WindowLength; ++j)
			{
				Edwards25519.Add(in multiples[i + j - 1], in cached, out EdwardsCompletedPoint sum);
				Edwards25519.ToExtended(in sum, out multiples[i + j]);
			}

			// The last entry is 2^(w − 1) times the base, so its double is the base of the next window.
			Edwards25519.Double(in multiples[i + WindowLength - 1], out windowBase);
		}

		EdwardsNielsPoint[] entries = new EdwardsNielsPoint[multiples.Length];
		Edwards25519.ToNielsVariableTime(multiples, entries);
		ulong[] storage = GC.AllocateUninitializedArray<ulong>(entries.Length * EntryLength + Alignment / sizeof(ulong) - 1, true);
		Span<ulong> packed = storage.AsSpan(AlignedStart(storage));

		for (int i = 0; i < entries.Length; ++i)
		{
			Span<ulong> entry = packed.Slice(i * EntryLength, EntryLength);
			Field25519.ToLimbs(in entries[i].YPlusX, entry.Slice(0, 4));
			Field25519.ToLimbs(in entries[i].YMinusX, entry.Slice(4, 4));
			Field25519.ToLimbs(in entries[i].TwoDXY, entry.Slice(8, 4));
		}

		return storage;
	}

	// Array data is aligned to its 8-byte elements, so the boundary falls on a whole limb.
	private static int AlignedStart(ulong[] storage)
	{
		nint address = Marshal.UnsafeAddrOfPinnedArrayElement(storage, 0);
		return (int)(-address & Alignment - 1) / sizeof(ulong);
	}
}
