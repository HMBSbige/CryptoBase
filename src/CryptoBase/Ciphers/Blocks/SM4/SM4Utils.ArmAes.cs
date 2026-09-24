using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal static partial class SM4Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadConstantsArmAes(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask)
	{
		preLo = Vector128.Create(0x078B37BB820EB23EUL, 0x9814A8241D912DA1UL).AsByte();
		preHi = Vector128.Create(0x37EB19C5F22EDC00UL, 0x3FE311CDFA26D408UL).AsByte();
		postLo = Vector128.Create(0x2098EA521EA6D46CUL, 0x47FF8D3579C1B30BUL).AsByte();
		postHi = Vector128.Create(0x2DCD7D9DB050E000UL, 0xED0DBD5D709020C0UL).AsByte();
		inverseShiftRows = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
		mask = Vector128.Create((byte)0x0F);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> AffineArmAes(Vector128<byte> x, Vector128<byte> lo, Vector128<byte> hi, Vector128<byte> mask)
	{
		Vector128<byte> low = Vector128.ShuffleNative(lo, x & mask);
		Vector128<byte> high = Vector128.ShuffleNative(hi, x >>> 4);
		return low ^ high;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> SubByteArmAes(Vector128<uint> x, Vector128<byte> preLo, Vector128<byte> preHi, Vector128<byte> postLo, Vector128<byte> postHi, Vector128<byte> inverseShiftRows, Vector128<byte> mask)
	{
		Vector128<byte> y = AffineArmAes(x.AsByte(), preLo, preHi, mask);
		y = AesArm.Encrypt(y, Vector128<byte>.Zero);
		y = AdvSimd.Arm64.VectorTableLookup(y, inverseShiftRows);
		return AffineArmAes(y, postLo, postHi, mask).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round2ArmAes
	(
		ref Vector128<uint> x0, ref Vector128<uint> x4, Vector128<uint> t0, Vector128<uint> t1,
		Vector128<byte> preLo, Vector128<byte> preHi, Vector128<byte> postLo, Vector128<byte> postHi, Vector128<byte> inverseShiftRows, Vector128<byte> mask
	)
	{
		t0 = SubByteArmAes(t0, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		t1 = SubByteArmAes(t1, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		x0 ^= LinearArm64(t0);
		x4 ^= LinearArm64(t1);
	}

	public static void Process4ArmAes(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		LoadConstantsArmAes(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		ref uint keys = ref rk.GetReference();

		for (int i = 0; i < 32; i += 4)
		{
			x0 ^= LinearArm64(SubByteArmAes(x1 ^ x2 ^ x3 ^ Vector128.Create(Unsafe.Add(ref keys, i)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
			x1 ^= LinearArm64(SubByteArmAes(x2 ^ x3 ^ x0 ^ Vector128.Create(Unsafe.Add(ref keys, i + 1)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
			x2 ^= LinearArm64(SubByteArmAes(x3 ^ x0 ^ x1 ^ Vector128.Create(Unsafe.Add(ref keys, i + 2)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
			x3 ^= LinearArm64(SubByteArmAes(x0 ^ x1 ^ x2 ^ Vector128.Create(Unsafe.Add(ref keys, i + 3)), preLo, preHi, postLo, postHi, inverseShiftRows, mask));
		}

		Store4Arm64(ref destination, x3, x2, x1, x0);
	}

	public static void Process8ArmAes(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		LoadConstantsArmAes(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
		Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		Load4Arm64(ref Unsafe.Add(ref source, 64), out Vector128<uint> x4, out Vector128<uint> x5, out Vector128<uint> x6, out Vector128<uint> x7);
		ref uint keys = ref rk.GetReference();

		for (int i = 0; i < 32; i += 4)
		{
			Vector128<uint> key = Vector128.Create(Unsafe.Add(ref keys, i));
			Round2ArmAes(ref x0, ref x4, x1 ^ x2 ^ x3 ^ key, x5 ^ x6 ^ x7 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			key = Vector128.Create(Unsafe.Add(ref keys, i + 1));
			Round2ArmAes(ref x1, ref x5, x2 ^ x3 ^ x0 ^ key, x6 ^ x7 ^ x4 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			key = Vector128.Create(Unsafe.Add(ref keys, i + 2));
			Round2ArmAes(ref x2, ref x6, x3 ^ x0 ^ x1 ^ key, x7 ^ x4 ^ x5 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
			key = Vector128.Create(Unsafe.Add(ref keys, i + 3));
			Round2ArmAes(ref x3, ref x7, x0 ^ x1 ^ x2 ^ key, x4 ^ x5 ^ x6 ^ key, preLo, preHi, postLo, postHi, inverseShiftRows, mask);
		}

		Store4Arm64(ref destination, x3, x2, x1, x0);
		Store4Arm64(ref Unsafe.Add(ref destination, 64), x7, x6, x5, x4);
	}
}
