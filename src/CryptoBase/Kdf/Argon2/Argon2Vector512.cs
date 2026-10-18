namespace CryptoBase.Kdf.Argon2;

internal readonly unsafe struct Argon2Vector512 : IArgon2Kernel
{
	public static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512F.IsSupported && Avx512BW.IsSupported;

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
	{
		Debug.Assert(IsSupported);

		ref ulong x = ref previous[0];

		Vector512<ulong> n0 = Vector512.LoadUnsafe(ref x, 0);
		Vector512<ulong> n1 = Vector512.LoadUnsafe(ref x, 8);
		Vector512<ulong> n2 = Vector512.LoadUnsafe(ref x, 16);
		Vector512<ulong> n3 = Vector512.LoadUnsafe(ref x, 24);
		Vector512<ulong> n4 = Vector512.LoadUnsafe(ref x, 32);
		Vector512<ulong> n5 = Vector512.LoadUnsafe(ref x, 40);
		Vector512<ulong> n6 = Vector512.LoadUnsafe(ref x, 48);
		Vector512<ulong> n7 = Vector512.LoadUnsafe(ref x, 56);
		Vector512<ulong> n8 = Vector512.LoadUnsafe(ref x, 64);
		Vector512<ulong> n9 = Vector512.LoadUnsafe(ref x, 72);
		Vector512<ulong> n10 = Vector512.LoadUnsafe(ref x, 80);
		Vector512<ulong> n11 = Vector512.LoadUnsafe(ref x, 88);
		Vector512<ulong> n12 = Vector512.LoadUnsafe(ref x, 96);
		Vector512<ulong> n13 = Vector512.LoadUnsafe(ref x, 104);
		Vector512<ulong> n14 = Vector512.LoadUnsafe(ref x, 112);
		Vector512<ulong> n15 = Vector512.LoadUnsafe(ref x, 120);

		CompressNext(ref reference[0], ref destination[0], xorDestination, ref n0, ref n1, ref n2, ref n3, ref n4, ref n5, ref n6, ref n7, ref n8, ref n9, ref n10, ref n11, ref n12, ref n13, ref n14, ref n15);
	}

	// Only segments that reference their own lane are chained: selecting among several lanes needs more general-purpose registers than x64 has, and the JIT then spills J1, which puts a store and a reload on the critical path.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static bool TryCompressChain(ref Argon2Block previous, ref Argon2Block segment, int startIndex, int segmentLength, Argon2ReferenceSet references, bool xorDestination)
	{
		Debug.Assert(IsSupported);

		if (!references.OwnLaneOnly)
		{
			return false;
		}

		ref ulong x = ref previous[0];
		Vector512<ulong> n0 = Vector512.LoadUnsafe(ref x, 0);
		Vector512<ulong> n1 = Vector512.LoadUnsafe(ref x, 8);
		Vector512<ulong> n2 = Vector512.LoadUnsafe(ref x, 16);
		Vector512<ulong> n3 = Vector512.LoadUnsafe(ref x, 24);
		Vector512<ulong> n4 = Vector512.LoadUnsafe(ref x, 32);
		Vector512<ulong> n5 = Vector512.LoadUnsafe(ref x, 40);
		Vector512<ulong> n6 = Vector512.LoadUnsafe(ref x, 48);
		Vector512<ulong> n7 = Vector512.LoadUnsafe(ref x, 56);
		Vector512<ulong> n8 = Vector512.LoadUnsafe(ref x, 64);
		Vector512<ulong> n9 = Vector512.LoadUnsafe(ref x, 72);
		Vector512<ulong> n10 = Vector512.LoadUnsafe(ref x, 80);
		Vector512<ulong> n11 = Vector512.LoadUnsafe(ref x, 88);
		Vector512<ulong> n12 = Vector512.LoadUnsafe(ref x, 96);
		Vector512<ulong> n13 = Vector512.LoadUnsafe(ref x, 104);
		Vector512<ulong> n14 = Vector512.LoadUnsafe(ref x, 112);
		Vector512<ulong> n15 = Vector512.LoadUnsafe(ref x, 120);

		for (int index = startIndex; index < segmentLength; ++index)
		{
			ref ulong y = ref (*references.LocateInOwnLane(n0.AsUInt32().ToScalar(), index))[0];
			CompressNext(ref y, ref Unsafe.Add(ref segment, index)[0], xorDestination, ref n0, ref n1, ref n2, ref n3, ref n4, ref n5, ref n6, ref n7, ref n8, ref n9, ref n10, ref n11, ref n12, ref n13, ref n14, ref n15);
		}

		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressNext
	(
		ref ulong reference, ref ulong state, bool xorDestination,
		ref Vector512<ulong> n0, ref Vector512<ulong> n1, ref Vector512<ulong> n2, ref Vector512<ulong> n3,
		ref Vector512<ulong> n4, ref Vector512<ulong> n5, ref Vector512<ulong> n6, ref Vector512<ulong> n7,
		ref Vector512<ulong> n8, ref Vector512<ulong> n9, ref Vector512<ulong> n10, ref Vector512<ulong> n11,
		ref Vector512<ulong> n12, ref Vector512<ulong> n13, ref Vector512<ulong> n14, ref Vector512<ulong> n15
	)
	{
		n0 ^= Vector512.LoadUnsafe(ref reference, 0);
		n1 ^= Vector512.LoadUnsafe(ref reference, 8);
		n2 ^= Vector512.LoadUnsafe(ref reference, 16);
		n3 ^= Vector512.LoadUnsafe(ref reference, 24);
		n4 ^= Vector512.LoadUnsafe(ref reference, 32);
		n5 ^= Vector512.LoadUnsafe(ref reference, 40);
		n6 ^= Vector512.LoadUnsafe(ref reference, 48);
		n7 ^= Vector512.LoadUnsafe(ref reference, 56);
		n8 ^= Vector512.LoadUnsafe(ref reference, 64);
		n9 ^= Vector512.LoadUnsafe(ref reference, 72);
		n10 ^= Vector512.LoadUnsafe(ref reference, 80);
		n11 ^= Vector512.LoadUnsafe(ref reference, 88);
		n12 ^= Vector512.LoadUnsafe(ref reference, 96);
		n13 ^= Vector512.LoadUnsafe(ref reference, 104);
		n14 ^= Vector512.LoadUnsafe(ref reference, 112);
		n15 ^= Vector512.LoadUnsafe(ref reference, 120);

		StoreR(ref state, xorDestination, n0, n1, n2, n3, n4, n5, n6, n7, 0);
		StoreR(ref state, xorDestination, n8, n9, n10, n11, n12, n13, n14, n15, 64);
		Permute(ref n0, ref n1, ref n2, ref n3, ref n4, ref n5, ref n6, ref n7, ref n8, ref n9, ref n10, ref n11, ref n12, ref n13, ref n14, ref n15);
		Finish(ref state, ref n0, ref n1, ref n2, ref n3, ref n4, ref n5, ref n6, ref n7, 0);
		Finish(ref state, ref n8, ref n9, ref n10, ref n11, ref n12, ref n13, ref n14, ref n15, 64);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreR(ref ulong state, bool xorDestination, Vector512<ulong> r0, Vector512<ulong> r1, Vector512<ulong> r2, Vector512<ulong> r3, Vector512<ulong> r4, Vector512<ulong> r5, Vector512<ulong> r6, Vector512<ulong> r7, nuint offset)
	{
		if (xorDestination)
		{
			r0 ^= Vector512.LoadUnsafe(ref state, offset);
			r1 ^= Vector512.LoadUnsafe(ref state, offset + 8);
			r2 ^= Vector512.LoadUnsafe(ref state, offset + 16);
			r3 ^= Vector512.LoadUnsafe(ref state, offset + 24);
			r4 ^= Vector512.LoadUnsafe(ref state, offset + 32);
			r5 ^= Vector512.LoadUnsafe(ref state, offset + 40);
			r6 ^= Vector512.LoadUnsafe(ref state, offset + 48);
			r7 ^= Vector512.LoadUnsafe(ref state, offset + 56);
		}

		r0.StoreUnsafe(ref state, offset);
		r1.StoreUnsafe(ref state, offset + 8);
		r2.StoreUnsafe(ref state, offset + 16);
		r3.StoreUnsafe(ref state, offset + 24);
		r4.StoreUnsafe(ref state, offset + 32);
		r5.StoreUnsafe(ref state, offset + 40);
		r6.StoreUnsafe(ref state, offset + 48);
		r7.StoreUnsafe(ref state, offset + 56);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Finish(ref ulong state, ref Vector512<ulong> n0, ref Vector512<ulong> n1, ref Vector512<ulong> n2, ref Vector512<ulong> n3, ref Vector512<ulong> n4, ref Vector512<ulong> n5, ref Vector512<ulong> n6, ref Vector512<ulong> n7, nuint offset)
	{
		n0 ^= Vector512.LoadUnsafe(ref state, offset);
		n1 ^= Vector512.LoadUnsafe(ref state, offset + 8);
		n2 ^= Vector512.LoadUnsafe(ref state, offset + 16);
		n3 ^= Vector512.LoadUnsafe(ref state, offset + 24);
		n4 ^= Vector512.LoadUnsafe(ref state, offset + 32);
		n5 ^= Vector512.LoadUnsafe(ref state, offset + 40);
		n6 ^= Vector512.LoadUnsafe(ref state, offset + 48);
		n7 ^= Vector512.LoadUnsafe(ref state, offset + 56);
		n0.StoreUnsafe(ref state, offset);
		n1.StoreUnsafe(ref state, offset + 8);
		n2.StoreUnsafe(ref state, offset + 16);
		n3.StoreUnsafe(ref state, offset + 24);
		n4.StoreUnsafe(ref state, offset + 32);
		n5.StoreUnsafe(ref state, offset + 40);
		n6.StoreUnsafe(ref state, offset + 48);
		n7.StoreUnsafe(ref state, offset + 56);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Permute
	(
		ref Vector512<ulong> n0, ref Vector512<ulong> n1, ref Vector512<ulong> n2, ref Vector512<ulong> n3,
		ref Vector512<ulong> n4, ref Vector512<ulong> n5, ref Vector512<ulong> n6, ref Vector512<ulong> n7,
		ref Vector512<ulong> n8, ref Vector512<ulong> n9, ref Vector512<ulong> n10, ref Vector512<ulong> n11,
		ref Vector512<ulong> n12, ref Vector512<ulong> n13, ref Vector512<ulong> n14, ref Vector512<ulong> n15
	)
	{
		// The two 256-bit halves of a row vector hold the same quarter of rows 2i and 2i + 1, so Permute4x64 diagonalizes each row within its half.
		Vector512<ulong> a0 = Avx512F.Shuffle4x128(n0, n2, 0b01_00_01_00);
		Vector512<ulong> b0 = Avx512F.Shuffle4x128(n0, n2, 0b11_10_11_10);
		Vector512<ulong> c0 = Avx512F.Shuffle4x128(n1, n3, 0b01_00_01_00);
		Vector512<ulong> d0 = Avx512F.Shuffle4x128(n1, n3, 0b11_10_11_10);
		Vector512<ulong> a1 = Avx512F.Shuffle4x128(n4, n6, 0b01_00_01_00);
		Vector512<ulong> b1 = Avx512F.Shuffle4x128(n4, n6, 0b11_10_11_10);
		Vector512<ulong> c1 = Avx512F.Shuffle4x128(n5, n7, 0b01_00_01_00);
		Vector512<ulong> d1 = Avx512F.Shuffle4x128(n5, n7, 0b11_10_11_10);
		Vector512<ulong> a2 = Avx512F.Shuffle4x128(n8, n10, 0b01_00_01_00);
		Vector512<ulong> b2 = Avx512F.Shuffle4x128(n8, n10, 0b11_10_11_10);
		Vector512<ulong> c2 = Avx512F.Shuffle4x128(n9, n11, 0b01_00_01_00);
		Vector512<ulong> d2 = Avx512F.Shuffle4x128(n9, n11, 0b11_10_11_10);
		Vector512<ulong> a3 = Avx512F.Shuffle4x128(n12, n14, 0b01_00_01_00);
		Vector512<ulong> b3 = Avx512F.Shuffle4x128(n12, n14, 0b11_10_11_10);
		Vector512<ulong> c3 = Avx512F.Shuffle4x128(n13, n15, 0b01_00_01_00);
		Vector512<ulong> d3 = Avx512F.Shuffle4x128(n13, n15, 0b11_10_11_10);

		G(ref a0, ref b0, ref c0, ref d0, ref a1, ref b1, ref c1, ref d1, ref a2, ref b2, ref c2, ref d2, ref a3, ref b3, ref c3, ref d3);

		// Diagonalizing a, c and d leaves b, which G finishes last, off the permutation path.
		a0 = Avx512F.Permute4x64(a0, 0b10_01_00_11);
		a1 = Avx512F.Permute4x64(a1, 0b10_01_00_11);
		a2 = Avx512F.Permute4x64(a2, 0b10_01_00_11);
		a3 = Avx512F.Permute4x64(a3, 0b10_01_00_11);
		c0 = Avx512F.Permute4x64(c0, 0b00_11_10_01);
		c1 = Avx512F.Permute4x64(c1, 0b00_11_10_01);
		c2 = Avx512F.Permute4x64(c2, 0b00_11_10_01);
		c3 = Avx512F.Permute4x64(c3, 0b00_11_10_01);
		d0 = Avx512F.Permute4x64(d0, 0b01_00_11_10);
		d1 = Avx512F.Permute4x64(d1, 0b01_00_11_10);
		d2 = Avx512F.Permute4x64(d2, 0b01_00_11_10);
		d3 = Avx512F.Permute4x64(d3, 0b01_00_11_10);

		G(ref a0, ref b0, ref c0, ref d0, ref a1, ref b1, ref c1, ref d1, ref a2, ref b2, ref c2, ref d2, ref a3, ref b3, ref c3, ref d3);

		a0 = Avx512F.Permute4x64(a0, 0b00_11_10_01);
		a1 = Avx512F.Permute4x64(a1, 0b00_11_10_01);
		a2 = Avx512F.Permute4x64(a2, 0b00_11_10_01);
		a3 = Avx512F.Permute4x64(a3, 0b00_11_10_01);
		c0 = Avx512F.Permute4x64(c0, 0b10_01_00_11);
		c1 = Avx512F.Permute4x64(c1, 0b10_01_00_11);
		c2 = Avx512F.Permute4x64(c2, 0b10_01_00_11);
		c3 = Avx512F.Permute4x64(c3, 0b10_01_00_11);
		d0 = Avx512F.Permute4x64(d0, 0b01_00_11_10);
		d1 = Avx512F.Permute4x64(d1, 0b01_00_11_10);
		d2 = Avx512F.Permute4x64(d2, 0b01_00_11_10);
		d3 = Avx512F.Permute4x64(d3, 0b01_00_11_10);

		n0 = Avx512F.Shuffle4x128(a0, b0, 0b01_00_01_00);
		n2 = Avx512F.Shuffle4x128(a0, b0, 0b11_10_11_10);
		n1 = Avx512F.Shuffle4x128(c0, d0, 0b01_00_01_00);
		n3 = Avx512F.Shuffle4x128(c0, d0, 0b11_10_11_10);
		n4 = Avx512F.Shuffle4x128(a1, b1, 0b01_00_01_00);
		n6 = Avx512F.Shuffle4x128(a1, b1, 0b11_10_11_10);
		n5 = Avx512F.Shuffle4x128(c1, d1, 0b01_00_01_00);
		n7 = Avx512F.Shuffle4x128(c1, d1, 0b11_10_11_10);
		n8 = Avx512F.Shuffle4x128(a2, b2, 0b01_00_01_00);
		n10 = Avx512F.Shuffle4x128(a2, b2, 0b11_10_11_10);
		n9 = Avx512F.Shuffle4x128(c2, d2, 0b01_00_01_00);
		n11 = Avx512F.Shuffle4x128(c2, d2, 0b11_10_11_10);
		n12 = Avx512F.Shuffle4x128(a3, b3, 0b01_00_01_00);
		n14 = Avx512F.Shuffle4x128(a3, b3, 0b11_10_11_10);
		n13 = Avx512F.Shuffle4x128(c3, d3, 0b01_00_01_00);
		n15 = Avx512F.Shuffle4x128(c3, d3, 0b11_10_11_10);

		// In the column phase each 128-bit lane holds one column: n[2r] covers columns 0..3 and n[2r + 1] columns 4..7 of row r, so (v0, ..., v15) of a column is (n0, n2, n4, ..., n14) or (n1, n3, n5, ..., n15) and diagonalizing stays within lanes.
		G(ref n0, ref n4, ref n8, ref n12, ref n2, ref n6, ref n10, ref n14, ref n1, ref n5, ref n9, ref n13, ref n3, ref n7, ref n11, ref n15);

		Vector512<ulong> rotatedA0 = Concat(n2, n0);
		Vector512<ulong> rotatedA1 = Concat(n0, n2);
		Vector512<ulong> rotatedC0 = Concat(n8, n10);
		Vector512<ulong> rotatedC1 = Concat(n10, n8);
		Vector512<ulong> rotatedA2 = Concat(n3, n1);
		Vector512<ulong> rotatedA3 = Concat(n1, n3);
		Vector512<ulong> rotatedC2 = Concat(n9, n11);
		Vector512<ulong> rotatedC3 = Concat(n11, n9);

		G(ref rotatedA0, ref n4, ref rotatedC0, ref n14, ref rotatedA1, ref n6, ref rotatedC1, ref n12, ref rotatedA2, ref n5, ref rotatedC2, ref n15, ref rotatedA3, ref n7, ref rotatedC3, ref n13);

		n0 = Concat(rotatedA0, rotatedA1);
		n2 = Concat(rotatedA1, rotatedA0);
		n8 = Concat(rotatedC1, rotatedC0);
		n10 = Concat(rotatedC0, rotatedC1);
		n1 = Concat(rotatedA2, rotatedA3);
		n3 = Concat(rotatedA3, rotatedA2);
		n9 = Concat(rotatedC3, rotatedC2);
		n11 = Concat(rotatedC2, rotatedC3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G
	(
		ref Vector512<ulong> a0, ref Vector512<ulong> b0, ref Vector512<ulong> c0, ref Vector512<ulong> d0,
		ref Vector512<ulong> a1, ref Vector512<ulong> b1, ref Vector512<ulong> c1, ref Vector512<ulong> d1,
		ref Vector512<ulong> a2, ref Vector512<ulong> b2, ref Vector512<ulong> c2, ref Vector512<ulong> d2,
		ref Vector512<ulong> a3, ref Vector512<ulong> b3, ref Vector512<ulong> c3, ref Vector512<ulong> d3
	)
	{
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		a2 = BlaMka(a2, b2);
		a3 = BlaMka(a3, b3);
		d0 = Avx512F.RotateRight(d0 ^ a0, 32);
		d1 = Avx512F.RotateRight(d1 ^ a1, 32);
		d2 = Avx512F.RotateRight(d2 ^ a2, 32);
		d3 = Avx512F.RotateRight(d3 ^ a3, 32);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		c2 = BlaMka(c2, d2);
		c3 = BlaMka(c3, d3);
		b0 = Avx512F.RotateRight(b0 ^ c0, 24);
		b1 = Avx512F.RotateRight(b1 ^ c1, 24);
		b2 = Avx512F.RotateRight(b2 ^ c2, 24);
		b3 = Avx512F.RotateRight(b3 ^ c3, 24);
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		a2 = BlaMka(a2, b2);
		a3 = BlaMka(a3, b3);
		d0 = Avx512F.RotateRight(d0 ^ a0, 16);
		d1 = Avx512F.RotateRight(d1 ^ a1, 16);
		d2 = Avx512F.RotateRight(d2 ^ a2, 16);
		d3 = Avx512F.RotateRight(d3 ^ a3, 16);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		c2 = BlaMka(c2, d2);
		c3 = BlaMka(c3, d3);
		b0 = Avx512F.RotateRight(b0 ^ c0, 63);
		b1 = Avx512F.RotateRight(b1 ^ c1, 63);
		b2 = Avx512F.RotateRight(b2 ^ c2, 63);
		b3 = Avx512F.RotateRight(b3 ^ c3, 63);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> BlaMka(Vector512<ulong> x, Vector512<ulong> y)
	{
		Vector512<ulong> product = Avx512F.Multiply(x.AsUInt32(), y.AsUInt32());
		return x + y + (product + product);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Concat(Vector512<ulong> left, Vector512<ulong> right)
	{
		return Avx512BW.AlignRight(right.AsByte(), left.AsByte(), 8).AsUInt64();
	}
}
