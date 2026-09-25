namespace CryptoBase.Ciphers.Blocks.SM4;

internal static class SM4KeySchedule
{
	private static ReadOnlySpan<uint> CK =>
	[
		0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
		0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
		0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
		0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
		0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
		0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
		0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
		0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
	];

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint L1(uint b)
	{
		return b ^ b.RotateLeft(13) ^ b.RotateLeft(23);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void InitRoundKeys(ref byte key, ref uint rk)
	{
		uint k0 = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref key)) ^ 0xa3b1bac6;
		uint k1 = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref key, 4))) ^ 0x56aa3350;
		uint k2 = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref key, 8))) ^ 0x677d9197;
		uint k3 = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref key, 12))) ^ 0xb27022dc;

		if (SM4Neon.IsSupported && !SM4ArmAes.IsSupported)
		{
			InitRoundKeysNeon(k0, k1, k2, k3, ref rk);
			return;
		}

		ref uint ck = ref CK.GetReference();

		for (int i = 0; i < 32; i += 4)
		{
			k0 ^= L1(SubByteKey(k1 ^ k2 ^ k3 ^ Unsafe.Add(ref ck, i)));
			Unsafe.Add(ref rk, i) = k0;

			k1 ^= L1(SubByteKey(k2 ^ k3 ^ k0 ^ Unsafe.Add(ref ck, i + 1)));
			Unsafe.Add(ref rk, i + 1) = k1;

			k2 ^= L1(SubByteKey(k3 ^ k0 ^ k1 ^ Unsafe.Add(ref ck, i + 2)));
			Unsafe.Add(ref rk, i + 2) = k2;

			k3 ^= L1(SubByteKey(k0 ^ k1 ^ k2 ^ Unsafe.Add(ref ck, i + 3)));
			Unsafe.Add(ref rk, i + 3) = k3;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void InitRoundKeysNeon(uint k0, uint k1, uint k2, uint k3, ref uint rk)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref SM4Neon.S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		Vector128<byte> tableSize = Vector128.Create((byte)64);
		Vector128<uint> x0 = Vector128.Create(k0);
		Vector128<uint> x1 = Vector128.Create(k1);
		Vector128<uint> x2 = Vector128.Create(k2);
		Vector128<uint> x3 = Vector128.Create(k3);
		ref uint ck = ref CK.GetReference();

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> index = (x1 ^ x2 ^ x3 ^ Vector128.Create(Unsafe.Add(ref ck, i))).AsByte();
			Vector128<byte> value = SM4Neon.Substitute(index, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, tableSize);

			Vector128<uint> t = value.AsUInt32();
			Vector128<uint> next = x0 ^ t ^ t.RotateLeftUInt32(13) ^ t.RotateLeftUInt32(23);
			Unsafe.Add(ref rk, i) = next.ToScalar();
			x0 = x1;
			x1 = x2;
			x2 = x3;
			x3 = next;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint SubByteKey(uint x)
	{
		if (SM4ArmAes.IsSupported)
		{
			return SM4ArmAes.SubByte(x);
		}

		if (SM4AesNI.IsSupported)
		{
			return SM4AesNI.SubByte(x);
		}

		return SM4Scalar.SubByte(x);
	}
}
