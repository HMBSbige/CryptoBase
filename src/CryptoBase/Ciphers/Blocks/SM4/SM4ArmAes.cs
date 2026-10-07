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
	private static void RoundLookahead2
	(
		ref Vector128<uint> x0, Vector128<uint> x2, Vector128<uint> x3, ref Vector128<uint> inputX,
		ref Vector128<uint> y0, Vector128<uint> y2, Vector128<uint> y3, ref Vector128<uint> inputY,
		Vector128<uint> nextKey,
		Vector128<byte> preLo, Vector128<byte> preHi, Vector128<byte> postLo, Vector128<byte> postHi, Vector128<byte> inverseShiftRows, Vector128<byte> mask
	)
	{
		Vector128<uint> othersX = x2 ^ x3 ^ nextKey;
		Vector128<uint> othersY = y2 ^ y3 ^ nextKey;
		Vector128<uint> valueX = Substitute(inputX, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		Vector128<uint> valueY = Substitute(inputY, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		inputX = SM4Linear.XorTransform(x0 ^ othersX, valueX);
		inputY = SM4Linear.XorTransform(y0 ^ othersY, valueY);
		x0 = othersX ^ inputX;
		y0 = othersY ^ inputY;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void RoundLookahead
	(
		ref Vector128<uint> r0, Vector128<uint> r2, Vector128<uint> r3, ref Vector128<uint> input, Vector128<uint> nextKey,
		Vector128<byte> preLo, Vector128<byte> preHi, Vector128<byte> postLo, Vector128<byte> postHi, Vector128<byte> inverseShiftRows, Vector128<byte> mask
	)
	{
		Vector128<uint> others = r2 ^ r3 ^ nextKey;
		input = SM4Linear.XorTransform(r0 ^ others, Substitute(input, preLo, preHi, postLo, postHi, inverseShiftRows, mask));
		r0 = others ^ input;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process4(ref uint keys, ref byte source, ref byte destination)
	{
		LoadConstants(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		SM4Layout.Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		Vector128<uint> input = x1 ^ x2 ^ x3 ^ Vector128.Create(keys);

		for (int i = 0; i < 28; i += 4)
		{
			RoundLookahead(ref x0, x2, x3, ref input, Vector128.Create(Unsafe.Add(ref keys, i + 1)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			RoundLookahead(ref x1, x3, x0, ref input, Vector128.Create(Unsafe.Add(ref keys, i + 2)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			RoundLookahead(ref x2, x0, x1, ref input, Vector128.Create(Unsafe.Add(ref keys, i + 3)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			RoundLookahead(ref x3, x1, x2, ref input, Vector128.Create(Unsafe.Add(ref keys, i + 4)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		}

		RoundLookahead(ref x0, x2, x3, ref input, Vector128.Create(Unsafe.Add(ref keys, 29)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		RoundLookahead(ref x1, x3, x0, ref input, Vector128.Create(Unsafe.Add(ref keys, 30)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		RoundLookahead(ref x2, x0, x1, ref input, Vector128.Create(Unsafe.Add(ref keys, 31)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		x3 = SM4Linear.XorTransform(x3, Substitute(input, preLo, preHi, postLo, postHi, inverseShiftRows, mask));

		SM4Layout.Store4Arm64(ref destination, x3, x2, x1, x0);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process8(ref uint keys, ref byte source, ref byte destination)
	{
		LoadConstants(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		SM4Layout.Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		SM4Layout.Load4Arm64(ref Unsafe.Add(ref source, 64), out Vector128<uint> x4, out Vector128<uint> x5, out Vector128<uint> x6, out Vector128<uint> x7);
		Vector128<uint> key = Vector128.Create(keys);
		Vector128<uint> inputX = x1 ^ x2 ^ x3 ^ key;
		Vector128<uint> inputY = x5 ^ x6 ^ x7 ^ key;

		for (int i = 0; i < 28; i += 4)
		{
			RoundLookahead2(ref x0, x2, x3, ref inputX, ref x4, x6, x7, ref inputY, Vector128.Create(Unsafe.Add(ref keys, i + 1)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			RoundLookahead2(ref x1, x3, x0, ref inputX, ref x5, x7, x4, ref inputY, Vector128.Create(Unsafe.Add(ref keys, i + 2)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			RoundLookahead2(ref x2, x0, x1, ref inputX, ref x6, x4, x5, ref inputY, Vector128.Create(Unsafe.Add(ref keys, i + 3)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			RoundLookahead2(ref x3, x1, x2, ref inputX, ref x7, x5, x6, ref inputY, Vector128.Create(Unsafe.Add(ref keys, i + 4)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		}

		RoundLookahead2(ref x0, x2, x3, ref inputX, ref x4, x6, x7, ref inputY, Vector128.Create(Unsafe.Add(ref keys, 29)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		RoundLookahead2(ref x1, x3, x0, ref inputX, ref x5, x7, x4, ref inputY, Vector128.Create(Unsafe.Add(ref keys, 30)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		RoundLookahead2(ref x2, x0, x1, ref inputX, ref x6, x4, x5, ref inputY, Vector128.Create(Unsafe.Add(ref keys, 31)), preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		Vector128<uint> valueX = Substitute(inputX, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		Vector128<uint> valueY = Substitute(inputY, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		x3 = SM4Linear.XorTransform(x3, valueX);
		x7 = SM4Linear.XorTransform(x7, valueY);

		SM4Layout.Store4Arm64(ref destination, x3, x2, x1, x0);
		SM4Layout.Store4Arm64(ref Unsafe.Add(ref destination, 64), x7, x6, x5, x4);
	}
}
