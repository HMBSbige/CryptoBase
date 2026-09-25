using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly struct SM4ArmAes : ISM4Kernel
{
	public static bool IsSupported => AdvSimd.Arm64.IsSupported && AesArm.IsSupported;

	public static int MaxBlocks => 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(IsSupported && width is 4 or 8 && count > 0 && count <= width);

		if (count != width)
		{
			SM4BlockDriver<SM4ArmAes>.ProcessPadded(width, count, ref rk, ref source, ref destination);
		}
		else if (width is 4)
		{
			Process4(ref rk, ref source, ref destination);
		}
		else
		{
			Process8(ref rk, ref source, ref destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint SubByte(uint x)
	{
		return Substitute(Vector128.CreateScalar(x).AsByte()).AsUInt32().ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Substitute(Vector128<byte> x)
	{
		LoadConstants(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		return Substitute(x.AsUInt32(), preLo, preHi, postLo, postHi, inverseShiftRows, mask).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadConstants(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask)
	{
		preLo = Vector128.Create(0x078B37BB820EB23EUL, 0x9814A8241D912DA1UL).AsByte();
		preHi = Vector128.Create(0x37EB19C5F22EDC00UL, 0x3FE311CDFA26D408UL).AsByte();
		postLo = Vector128.Create(0x2098EA521EA6D46CUL, 0x47FF8D3579C1B30BUL).AsByte();
		postHi = Vector128.Create(0x2DCD7D9DB050E000UL, 0xED0DBD5D709020C0UL).AsByte();
		inverseShiftRows = SM4AesConstants.InverseShiftRows;
		mask = Vector128.Create((byte)0x0F);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Affine(Vector128<byte> x, Vector128<byte> lo, Vector128<byte> hi, Vector128<byte> mask)
	{
		Vector128<byte> low = Vector128.ShuffleNative(lo, x & mask);
		Vector128<byte> high = Vector128.ShuffleNative(hi, x >>> 4);
		return low ^ high;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Substitute(Vector128<uint> x, Vector128<byte> preLo, Vector128<byte> preHi, Vector128<byte> postLo, Vector128<byte> postHi, Vector128<byte> inverseShiftRows, Vector128<byte> mask)
	{
		Vector128<byte> y = Affine(x.AsByte(), preLo, preHi, mask);
		y = AesArm.Encrypt(y, Vector128<byte>.Zero);
		y = AdvSimd.Arm64.VectorTableLookup(y, inverseShiftRows);
		return Affine(y, postLo, postHi, mask).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round2
	(
		ref Vector128<uint> x0, ref Vector128<uint> x4, Vector128<uint> t0, Vector128<uint> t1,
		Vector128<byte> preLo, Vector128<byte> preHi, Vector128<byte> postLo, Vector128<byte> postHi, Vector128<byte> inverseShiftRows, Vector128<byte> mask
	)
	{
		t0 = Substitute(t0, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		t1 = Substitute(t1, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		x0 ^= SM4Linear.Transform(t0);
		x4 ^= SM4Linear.Transform(t1);
	}

	private static void Process4(ref uint keys, ref byte source, ref byte destination)
	{
		LoadConstants(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		SM4Layout.Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);

		for (int i = 0; i < 32; i += 4)
		{
			x0 ^= SM4Linear.Transform(Substitute(x1 ^ x2 ^ x3 ^ Vector128.Create(Unsafe.Add(ref keys, i)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
			x1 ^= SM4Linear.Transform(Substitute(x2 ^ x3 ^ x0 ^ Vector128.Create(Unsafe.Add(ref keys, i + 1)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
			x2 ^= SM4Linear.Transform(Substitute(x3 ^ x0 ^ x1 ^ Vector128.Create(Unsafe.Add(ref keys, i + 2)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
			x3 ^= SM4Linear.Transform(Substitute(x0 ^ x1 ^ x2 ^ Vector128.Create(Unsafe.Add(ref keys, i + 3)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
		}

		SM4Layout.Store4Arm64(ref destination, x3, x2, x1, x0);
	}

	private static void Process8(ref uint keys, ref byte source, ref byte destination)
	{
		LoadConstants(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		SM4Layout.Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		SM4Layout.Load4Arm64(ref Unsafe.Add(ref source, 64), out Vector128<uint> x4, out Vector128<uint> x5, out Vector128<uint> x6, out Vector128<uint> x7);

		for (int i = 0; i < 32; i += 4)
		{
			Vector128<uint> key = Vector128.Create(Unsafe.Add(ref keys, i));
			Round2(ref x0, ref x4, x1 ^ x2 ^ x3 ^ key, x5 ^ x6 ^ x7 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			key = Vector128.Create(Unsafe.Add(ref keys, i + 1));
			Round2(ref x1, ref x5, x2 ^ x3 ^ x0 ^ key, x6 ^ x7 ^ x4 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			key = Vector128.Create(Unsafe.Add(ref keys, i + 2));
			Round2(ref x2, ref x6, x3 ^ x0 ^ x1 ^ key, x7 ^ x4 ^ x5 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			key = Vector128.Create(Unsafe.Add(ref keys, i + 3));
			Round2(ref x3, ref x7, x0 ^ x1 ^ x2 ^ key, x4 ^ x5 ^ x6 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		}

		SM4Layout.Store4Arm64(ref destination, x3, x2, x1, x0);
		SM4Layout.Store4Arm64(ref Unsafe.Add(ref destination, 64), x7, x6, x5, x4);
	}
}
