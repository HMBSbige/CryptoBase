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
		Rounds16V512(ref rk, ref v0, ref v1, ref v2, ref v3);
		SM4Layout.Store16X86(count, ref destination, 0, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process32V512(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load16X86(count, ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		SM4Layout.Load16X86(count - 16, ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		Rounds32V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3);
		SM4Layout.Store16X86(count, ref destination, 0, a0, a1, a2, a3);
		SM4Layout.Store16X86(count - 16, ref destination, 256, b0, b1, b2, b3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process64V512(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4DirectPolicy policy = default;
		ProcessUpTo64V512(count, ref rk, ref source, ref destination, ref policy);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process64FullV512<TPolicy>(ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		policy.Prepare16(ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		policy.Prepare16(ref source, 512, out Vector512<byte> c0, out Vector512<byte> c1, out Vector512<byte> c2, out Vector512<byte> c3);
		policy.Prepare16(ref source, 768, out Vector512<byte> d0, out Vector512<byte> d1, out Vector512<byte> d2, out Vector512<byte> d3);
		Rounds64V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
		policy.Finish16(ref source, ref destination, 256, b0, b1, b2, b3);
		policy.Finish16(ref source, ref destination, 512, c0, c1, c2, c3);
		policy.Finish16(ref source, ref destination, 768, d0, d1, d2, d3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process16FullV512<TPolicy>(ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		Rounds16V512(ref rk, ref a0, ref a1, ref a2, ref a3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process32FullV512<TPolicy>(ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		policy.Prepare16(ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		Rounds32V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
		policy.Finish16(ref source, ref destination, 256, b0, b1, b2, b3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process48FullV512<TPolicy>(ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		policy.Prepare16(ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		policy.Prepare16(ref source, 512, out Vector512<byte> c0, out Vector512<byte> c1, out Vector512<byte> c2, out Vector512<byte> c3);
		Rounds48V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
		policy.Finish16(ref source, ref destination, 256, b0, b1, b2, b3);
		policy.Finish16(ref source, ref destination, 512, c0, c1, c2, c3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process16PartialV512<TPolicy>(int count, ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.PreparePartial16(count, ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		Rounds16V512(ref rk, ref a0, ref a1, ref a2, ref a3);
		policy.FinishPartial16(count, ref source, ref destination, 0, a0, a1, a2, a3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process32PartialV512<TPolicy>(int count, ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		policy.PreparePartial16(count - 16, ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		Rounds32V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
		policy.FinishPartial16(count - 16, ref source, ref destination, 256, b0, b1, b2, b3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process48PartialV512<TPolicy>(int count, ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		policy.Prepare16(ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		policy.PreparePartial16(count - 32, ref source, 512, out Vector512<byte> c0, out Vector512<byte> c1, out Vector512<byte> c2, out Vector512<byte> c3);
		Rounds48V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
		policy.Finish16(ref source, ref destination, 256, b0, b1, b2, b3);
		policy.FinishPartial16(count - 32, ref source, ref destination, 512, c0, c1, c2, c3);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process64PartialV512<TPolicy>(int count, ref uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		policy.Prepare16(ref source, 0, out Vector512<byte> a0, out Vector512<byte> a1, out Vector512<byte> a2, out Vector512<byte> a3);
		policy.Prepare16(ref source, 256, out Vector512<byte> b0, out Vector512<byte> b1, out Vector512<byte> b2, out Vector512<byte> b3);
		policy.Prepare16(ref source, 512, out Vector512<byte> c0, out Vector512<byte> c1, out Vector512<byte> c2, out Vector512<byte> c3);
		policy.PreparePartial16(count - 48, ref source, 768, out Vector512<byte> d0, out Vector512<byte> d1, out Vector512<byte> d2, out Vector512<byte> d3);
		Rounds64V512(ref rk, ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);
		policy.Finish16(ref source, ref destination, 0, a0, a1, a2, a3);
		policy.Finish16(ref source, ref destination, 256, b0, b1, b2, b3);
		policy.Finish16(ref source, ref destination, 512, c0, c1, c2, c3);
		policy.FinishPartial16(count - 48, ref source, ref destination, 768, d0, d1, d2, d3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds16V512(ref uint rk, ref Vector512<byte> a0, ref Vector512<byte> a1, ref Vector512<byte> a2, ref Vector512<byte> a3)
	{
		for (nuint i = 0; i < 32; i += 4)
		{
			Round(ref a0, a1, a2, a3, Vector512.Create(Unsafe.Add(ref rk, i)).AsByte());
			Round(ref a1, a2, a3, a0, Vector512.Create(Unsafe.Add(ref rk, i + 1)).AsByte());
			Round(ref a2, a3, a0, a1, Vector512.Create(Unsafe.Add(ref rk, i + 2)).AsByte());
			Round(ref a3, a0, a1, a2, Vector512.Create(Unsafe.Add(ref rk, i + 3)).AsByte());
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds32V512
	(
		ref uint rk,
		ref Vector512<byte> a0, ref Vector512<byte> a1, ref Vector512<byte> a2, ref Vector512<byte> a3,
		ref Vector512<byte> b0, ref Vector512<byte> b1, ref Vector512<byte> b2, ref Vector512<byte> b3
	)
	{
		for (nuint i = 0; i < 32; i += 4)
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
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds48V512
	(
		ref uint rk,
		ref Vector512<byte> a0, ref Vector512<byte> a1, ref Vector512<byte> a2, ref Vector512<byte> a3,
		ref Vector512<byte> b0, ref Vector512<byte> b1, ref Vector512<byte> b2, ref Vector512<byte> b3,
		ref Vector512<byte> c0, ref Vector512<byte> c1, ref Vector512<byte> c2, ref Vector512<byte> c3
	)
	{
		for (nuint i = 0; i < 32; i += 4)
		{
			Vector512<byte> key = Vector512.Create(Unsafe.Add(ref rk, i)).AsByte();
			Round(ref a0, a1, a2, a3, key);
			Round(ref b0, b1, b2, b3, key);
			Round(ref c0, c1, c2, c3, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 1)).AsByte();
			Round(ref a1, a2, a3, a0, key);
			Round(ref b1, b2, b3, b0, key);
			Round(ref c1, c2, c3, c0, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 2)).AsByte();
			Round(ref a2, a3, a0, a1, key);
			Round(ref b2, b3, b0, b1, key);
			Round(ref c2, c3, c0, c1, key);

			key = Vector512.Create(Unsafe.Add(ref rk, i + 3)).AsByte();
			Round(ref a3, a0, a1, a2, key);
			Round(ref b3, b0, b1, b2, key);
			Round(ref c3, c0, c1, c2, key);
		}
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
		for (nuint i = 0; i < 32; i += 4)
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
