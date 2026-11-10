namespace CryptoBase.EllipticCurves;

// Window i holds j·2^(wi)·P for j from 1 to 2^(w − 1), w = GeneratorWindowWidth, each entry as TField.Pack writes it: P is G for the table here and the public point of each ECPointTable. The entries start on a 64-byte boundary, so that a 64-byte entry fills one cache line.
internal static class ECGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	// Pinned, so that the boundary stays where Start finds it.
	// ReSharper disable once StaticMemberInGenericType
	private static readonly ulong[] Storage = BuildGenerator();

	// ReSharper disable once StaticMemberInGenericType
	private static readonly int Start = AlignedScratch.AlignedStart(Storage);

	internal static int WindowCount => ECGroup<TCurve, TField, TOrder>.DigitCount(TCurve.GeneratorWindowWidth);

	internal static int WindowLength => 1 << TCurve.GeneratorWindowWidth - 1;

	internal static int EntryLength => 2 * TField.PackedLength;

	internal static int Length => WindowCount * WindowLength * EntryLength;

	internal static ReadOnlySpan<ulong> Windows => new(Storage, Start, Length);

	// index counts entries across the windows and must be public, as the address read depends on it.
	internal static void Read(int index, out AffinePoint<TField> result)
	{
		Read(Windows, index, out result);
	}

	// The windows of a point P on the curve, from AlignedScratch.AlignedStart on in the pinned array returned. P is public, so the time may depend on it. A chain of doublings gives the bases B = 2^(wi)·P, by the kernels of TCurve where it has them or FillBases otherwise, made affine at once, and the kernels of TCurve where it has them or FillWindows otherwise fill the windows from them.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static ulong[] Build(in AffinePoint<TField> point)
	{
		Debug.Assert(WindowLength >= 2);

		int windowCount = WindowCount;
		int windowLength = WindowLength;
		ulong[] storage = AlignedScratch.AllocatePinned(Length);
		Span<ulong> windows = storage.AsSpan(AlignedScratch.AlignedStart(storage), Length);
		JacobianPoint<TField>[] bases = new JacobianPoint<TField>[windowCount];
		AffinePoint<TField>[] affineBases = new AffinePoint<TField>[windowCount];

		if (!TCurve.TryFillBases<TField, TOrder>(in point, bases))
		{
			FillBases(in point, bases);
		}

		// No base is the point at infinity: 2^(wi) is no multiple of the prime n.
		ECGroup<TCurve, TField, TOrder>.ToAffineVariableTime(bases, affineBases);

		for (int i = 0; i < windowCount; ++i)
		{
			Write(windows, i * windowLength, in affineBases[i]);
		}

		if (!TCurve.TryFillWindows<TField, TOrder>(windows))
		{
			FillWindows(windows);
		}

		return storage;
	}

	// Sets bases[i] to 2^(wi)·P, one doubling after another. P is public, so the time may depend on it.
	internal static void FillBases(in AffinePoint<TField> point, Span<JacobianPoint<TField>> bases)
	{
		JacobianPoint<TField>.FromAffine(in point, out bases[0]);

		for (int i = 1; i < bases.Length; ++i)
		{
			ECGroup<TCurve, TField, TOrder>.Double(in bases[i - 1], out bases[i]);

			for (int k = 1; k < TCurve.GeneratorWindowWidth; ++k)
			{
				ECGroup<TCurve, TField, TOrder>.Double(in bases[i], out bases[i]);
			}
		}
	}

	// Fills entries 2 to WindowLength of each window from entry 1, its base: each round r from 1 to w − 1 gives entries 2^(r − 1) + 1 to 2^r of every window, one inversion for the round, as AddRound describes. The windows are public, so the time may depend on them.
	internal static void FillWindows(Span<ulong> windows)
	{
		Debug.Assert(windows.Length == Length);

		TField[] products = new TField[WindowCount * WindowLength / 2];

		for (int half = 1; half < WindowLength; half *= 2)
		{
			AddRound(windows, half, products);
		}
	}

	// Entry index of windows, which counts entries across the windows.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Read(ReadOnlySpan<ulong> windows, int index, out AffinePoint<TField> result)
	{
		Unsafe.SkipInit(out result);
		windows.Slice(index * EntryLength, EntryLength).CopyTo(MemoryMarshal.Cast<AffinePoint<TField>, ulong>(new Span<AffinePoint<TField>>(ref result)));
		TField.Unpack(ref result);
	}

	private static ulong[] BuildGenerator()
	{
		ECGroup<TCurve, TField, TOrder>.Generator(out AffinePoint<TField> generator);
		return Build(in generator);
	}

	// Entries half + 1 to 2·half of every window, from the entries up to half: entry half + m is entry half plus entry m for m < half, and twice entry half for m = half. For P1 = (x1, y1), entry half, the affine sum with P2 = (x2, y2) takes λ = (y2 − y1)/(x2 − x1) and the double λ = 3(x1² − 1)/(2·y1), as a = −3; both give x3 = λ² − x1 − x2, x2 = x1 for the double, and y3 = λ(x1 − x3) − y1. In window i the two entries of a sum are equal or opposite only if n divides (half ∓ m)·2^(wi), so half ∓ m, which lies in [1, 2^w); and the double has y1 ≠ 0, as the group has odd order.
	// products[s] is the product of the denominators of the sums 0 to s, so that one inversion of the last gives the inverse of each denominator, from the last sum back: with I the inverse of the product up to s, I·products[s − 1] is the inverse of denominator s and I·denominator s that of the product up to s − 1.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void AddRound(Span<ulong> windows, int half, Span<TField> products)
	{
		int windowCount = WindowCount;
		int windowLength = WindowLength;
		Unsafe.SkipInit(out AffinePoint<TField> first);
		Unsafe.SkipInit(out AffinePoint<TField> second);
		Unsafe.SkipInit(out TField denominator);
		Unsafe.SkipInit(out TField numerator);
		TField product = TField.One;
		int sum = 0;

		for (int i = 0; i < windowCount; ++i)
		{
			int window = i * windowLength;
			Read(windows, window + half - 1, out first);

			for (int m = 1; m <= half; ++m)
			{
				Read(windows, window + m - 1, out second);
				Denominator(in first, in second, m == half, out denominator);
				TField.Multiply(in product, in denominator, out product);
				products[sum++] = product;
			}
		}

		TField.InvertVariableTime(in product, out TField inverse);
		Unsafe.SkipInit(out AffinePoint<TField> result);

		for (int i = windowCount - 1; i >= 0; --i)
		{
			int window = i * windowLength;
			Read(windows, window + half - 1, out first);

			for (int m = half; m >= 1; --m)
			{
				Read(windows, window + m - 1, out second);
				Terms(in first, in second, m == half, out denominator, out numerator);
				--sum;

				if (sum is not 0)
				{
					TField.Multiply(in inverse, in products[sum - 1], out TField lambda);
					TField.Multiply(in inverse, in denominator, out inverse);
					TField.Multiply(in numerator, in lambda, out lambda);
					Combine(in first, in second, in lambda, out result);
				}
				else
				{
					TField.Multiply(in numerator, in inverse, out TField lambda);
					Combine(in first, in second, in lambda, out result);
				}

				Write(windows, window + half + m - 1, in result);
			}
		}
	}

	// The denominator and the numerator of λ for first + second, or for twice first if doubling, in which case second is first.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Terms(in AffinePoint<TField> first, in AffinePoint<TField> second, bool doubling, out TField denominator, out TField numerator)
	{
		if (doubling)
		{
			TField.Add(in first.Y, in first.Y, out denominator);
			TField.Square(in first.X, out numerator);
			TField.Subtract(in numerator, in TField.One, out numerator);
			TField.Add(in numerator, in numerator, out TField twice);
			TField.Add(in twice, in numerator, out numerator);
		}
		else
		{
			TField.Subtract(in second.X, in first.X, out denominator);
			TField.Subtract(in second.Y, in first.Y, out numerator);
		}
	}

	// The denominator of Terms alone, for the chain of products, which does not take the numerator.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Denominator(in AffinePoint<TField> first, in AffinePoint<TField> second, bool doubling, out TField denominator)
	{
		if (doubling)
		{
			TField.Add(in first.Y, in first.Y, out denominator);
		}
		else
		{
			TField.Subtract(in second.X, in first.X, out denominator);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Combine(in AffinePoint<TField> first, in AffinePoint<TField> second, in TField lambda, out AffinePoint<TField> result)
	{
		TField.Square(in lambda, out result.X);
		TField.Subtract(in result.X, in first.X, out result.X);
		TField.Subtract(in result.X, in second.X, out result.X);
		TField.Subtract(in first.X, in result.X, out result.Y);
		TField.Multiply(in lambda, in result.Y, out result.Y);
		TField.Subtract(in result.Y, in first.Y, out result.Y);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Write(Span<ulong> windows, int index, in AffinePoint<TField> point)
	{
		TField.Pack(in point, windows.Slice(index * EntryLength, EntryLength));
	}
}
