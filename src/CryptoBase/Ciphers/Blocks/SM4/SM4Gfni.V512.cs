namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<byte> Substitute(Vector512<byte> x)
	{
		x = Gfni.V512.GaloisFieldAffineTransform(x, Vector512.Create(PreAffine).AsByte(), PreConstant);
		return Gfni.V512.GaloisFieldAffineTransformInverse(x, Vector512.Create(PostAffine).AsByte(), PostConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector512<byte> r0, Vector512<byte> r1, Vector512<byte> r2, Vector512<byte> r3, Vector512<byte> key)
	{
		Vector512<byte> x = Substitute(key ^ r1 ^ r2 ^ r3);
		r0 = SM4Linear.XorTransform(r0.AsUInt32(), x.AsUInt32()).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process16V512(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load16X86(count, ref source, 0, out Vector512<byte> v0, out Vector512<byte> v1, out Vector512<byte> v2, out Vector512<byte> v3);

		for (int i = 0; i < 32; i += 4)
		{
			Round(ref v0, v1, v2, v3, Vector512.Create(Unsafe.Add(ref rk, i)).AsByte());
			Round(ref v1, v2, v3, v0, Vector512.Create(Unsafe.Add(ref rk, i + 1)).AsByte());
			Round(ref v2, v3, v0, v1, Vector512.Create(Unsafe.Add(ref rk, i + 2)).AsByte());
			Round(ref v3, v0, v1, v2, Vector512.Create(Unsafe.Add(ref rk, i + 3)).AsByte());
		}

		SM4Layout.Store16X86(count, ref destination, 0, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process32V512(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load16X86(count, ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		SM4Layout.Load16X86(count - 16, ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);

		for (int i = 0; i < 32; i += 4)
		{
			Vector512<byte> key = Vector512.Create(Unsafe.Add(ref rk, i)).AsByte();
			Round(ref a0, a1, a2, a3, key);
			Round(ref b0, b1, b2, b3, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 1)).AsByte();
			Round(ref a1, a2, a3, a0, key);
			Round(ref b1, b2, b3, b0, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 2)).AsByte();
			Round(ref a2, a3, a0, a1, key);
			Round(ref b2, b3, b0, b1, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 3)).AsByte();
			Round(ref a3, a0, a1, a2, key);
			Round(ref b3, b0, b1, b2, key);
		}

		SM4Layout.Store16X86(count, ref destination, 0, a0, a1, a2, a3);
		SM4Layout.Store16X86(count - 16, ref destination, 256, b0, b1, b2, b3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process64V512(int count, ref uint rk, ref byte source, ref byte destination)
	{
		if (count is 64)
		{
			Process64FullV512(ref rk, ref source, ref destination);
			return;
		}

		Load16V512(count, ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		Load16V512(count - 16, ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		Load16V512(count - 32, ref source, 512, out Vector512<byte> c0, out Vector512<byte> c1, out Vector512<byte> c2, out Vector512<byte> c3);
		Load16V512(count - 48, ref source, 768, out Vector512<byte> d0, out Vector512<byte> d1, out Vector512<byte> d2, out Vector512<byte> d3);
		Rounds64PartialV512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);
		Store16V512(count, ref destination, 0, a0, a1, a2, a3);
		Store16V512(count - 16, ref destination, 256, b0, b1, b2, b3);
		Store16V512(count - 32, ref destination, 512, c0, c1, c2, c3);
		Store16V512(count - 48, ref destination, 768, d0, d1, d2, d3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process64FullV512(ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load16X86(16, ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		SM4Layout.Load16X86(16, ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		SM4Layout.Load16X86(16, ref source, 512, out Vector512<byte> c0, out Vector512<byte> c1, out Vector512<byte> c2, out Vector512<byte> c3);
		SM4Layout.Load16X86(16, ref source, 768, out Vector512<byte> d0, out Vector512<byte> d1, out Vector512<byte> d2, out Vector512<byte> d3);
		Rounds64V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);
		SM4Layout.Store16X86(16, ref destination, 0, a0, a1, a2, a3);
		SM4Layout.Store16X86(16, ref destination, 256, b0, b1, b2, b3);
		SM4Layout.Store16X86(16, ref destination, 512, c0, c1, c2, c3);
		SM4Layout.Store16X86(16, ref destination, 768, d0, d1, d2, d3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Load16V512(int count, ref byte source, nuint offset, out Vector512<byte> x0, out Vector512<byte> x1, out Vector512<byte> x2, out Vector512<byte> x3)
	{
		SM4Layout.Load16X86(count, ref source, offset, out x0, out x1, out x2, out x3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Store16V512(int count, ref byte destination, nuint offset, Vector512<byte> x0, Vector512<byte> x1, Vector512<byte> x2, Vector512<byte> x3)
	{
		SM4Layout.Store16X86(count, ref destination, offset, x0, x1, x2, x3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Rounds64PartialV512
	(
		ref uint rk,
		ref Vector512<byte> x0, ref Vector512<byte> x1, ref Vector512<byte> x2, ref Vector512<byte> x3,
		ref Vector512<byte> x4, ref Vector512<byte> x5, ref Vector512<byte> x6, ref Vector512<byte> x7,
		ref Vector512<byte> x8, ref Vector512<byte> x9, ref Vector512<byte> x10, ref Vector512<byte> x11,
		ref Vector512<byte> x12, ref Vector512<byte> x13, ref Vector512<byte> x14, ref Vector512<byte> x15
	)
	{
		// Copy ref parameters into locals to keep round state in registers.
		Vector512<byte> a0 = x0, a1 = x1, a2 = x2, a3 = x3;
		Vector512<byte> b0 = x4, b1 = x5, b2 = x6, b3 = x7;
		Vector512<byte> c0 = x8, c1 = x9, c2 = x10, c3 = x11;
		Vector512<byte> d0 = x12, d1 = x13, d2 = x14, d3 = x15;

		Rounds64V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);

		(x0, x1, x2, x3) = (a0, a1, a2, a3);
		(x4, x5, x6, x7) = (b0, b1, b2, b3);
		(x8, x9, x10, x11) = (c0, c1, c2, c3);
		(x12, x13, x14, x15) = (d0, d1, d2, d3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds64V512
	(
		ref uint rk,
		ref Vector512<byte> a0, ref Vector512<byte> a1, ref Vector512<byte> a2, ref Vector512<byte> a3,
		ref Vector512<byte> b0, ref Vector512<byte> b1, ref Vector512<byte> b2, ref Vector512<byte> b3,
		ref Vector512<byte> c0, ref Vector512<byte> c1, ref Vector512<byte> c2, ref Vector512<byte> c3,
		ref Vector512<byte> d0, ref Vector512<byte> d1, ref Vector512<byte> d2, ref Vector512<byte> d3
	)
	{
		for (int i = 0; i < 32; i += 4)
		{
			Vector512<byte> key = Vector512.Create(Unsafe.Add(ref rk, i)).AsByte();
			Round(ref a0, a1, a2, a3, key);
			Round(ref b0, b1, b2, b3, key);
			Round(ref c0, c1, c2, c3, key);
			Round(ref d0, d1, d2, d3, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 1)).AsByte();
			Round(ref a1, a2, a3, a0, key);
			Round(ref b1, b2, b3, b0, key);
			Round(ref c1, c2, c3, c0, key);
			Round(ref d1, d2, d3, d0, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 2)).AsByte();
			Round(ref a2, a3, a0, a1, key);
			Round(ref b2, b3, b0, b1, key);
			Round(ref c2, c3, c0, c1, key);
			Round(ref d2, d3, d0, d1, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 3)).AsByte();
			Round(ref a3, a0, a1, a2, key);
			Round(ref b3, b0, b1, b2, key);
			Round(ref c3, c0, c1, c2, key);
			Round(ref d3, d0, d1, d2, key);
		}
	}
}
