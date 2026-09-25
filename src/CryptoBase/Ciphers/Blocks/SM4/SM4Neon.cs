namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly struct SM4Neon : ISM4Kernel
{
	internal static ReadOnlySpan<byte> S =>
	[
		0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
		0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
		0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
		0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
		0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
		0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
		0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
		0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
		0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
		0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
		0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
		0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
		0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
		0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
		0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
	];

	public static bool IsSupported => AdvSimd.Arm64.IsSupported;

	public static int MaxBlocks => 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(IsSupported && width is 4 or 8 && count > 0 && count <= width);

		if (count != width)
		{
			SM4BlockDriver<SM4Neon>.ProcessPadded(width, count, ref rk, ref source, ref destination);
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
	internal static unsafe Vector128<byte> Substitute(Vector128<byte> index)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		return Substitute(index, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, Vector128.Create((byte)64));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Substitute
	(
		Vector128<byte> index,
		Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3,
		Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7,
		Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11,
		Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15,
		Vector128<byte> tableSize
	)
	{
		Vector128<byte> value = AdvSimd.Arm64.VectorTableLookup((s0, s1, s2, s3), index);
		index -= tableSize;
		value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s4, s5, s6, s7), index);
		index -= tableSize;
		value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s8, s9, s10, s11), index);
		index -= tableSize;
		return AdvSimd.Arm64.VectorTableLookupExtension(value, (s12, s13, s14, s15), index);
	}

	private static unsafe void Process4(ref uint keys, ref byte source, ref byte destination)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		Vector128<byte> tableSize = Vector128.Create((byte)64);
		SM4Layout.Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> index = (x1 ^ x2 ^ x3 ^ Vector128.Create(Unsafe.Add(ref keys, i))).AsByte();
			Vector128<byte> value = Substitute(index, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, tableSize);

			Vector128<uint> next = x0 ^ SM4Linear.Transform(value.AsUInt32());
			x0 = x1;
			x1 = x2;
			x2 = x3;
			x3 = next;
		}

		SM4Layout.Store4Arm64(ref destination, x3, x2, x1, x0);
	}

	private static unsafe void Process8(ref uint keys, ref byte source, ref byte destination)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		Vector128<byte> tableSize = Vector128.Create((byte)64);
		SM4Layout.Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		SM4Layout.Load4Arm64(ref Unsafe.Add(ref source, 64), out Vector128<uint> y0, out Vector128<uint> y1, out Vector128<uint> y2, out Vector128<uint> y3);

		for (int i = 0; i < 32; ++i)
		{
			Vector128<uint> key = Vector128.Create(Unsafe.Add(ref keys, i));
			Vector128<byte> indexX = (x1 ^ x2 ^ x3 ^ key).AsByte();
			Vector128<byte> indexY = (y1 ^ y2 ^ y3 ^ key).AsByte();

			Vector128<byte> valueX = AdvSimd.Arm64.VectorTableLookup((s0, s1, s2, s3), indexX);
			Vector128<byte> valueY = AdvSimd.Arm64.VectorTableLookup((s0, s1, s2, s3), indexY);
			indexX -= tableSize;
			indexY -= tableSize;
			valueX = AdvSimd.Arm64.VectorTableLookupExtension(valueX, (s4, s5, s6, s7), indexX);
			valueY = AdvSimd.Arm64.VectorTableLookupExtension(valueY, (s4, s5, s6, s7), indexY);
			indexX -= tableSize;
			indexY -= tableSize;
			valueX = AdvSimd.Arm64.VectorTableLookupExtension(valueX, (s8, s9, s10, s11), indexX);
			valueY = AdvSimd.Arm64.VectorTableLookupExtension(valueY, (s8, s9, s10, s11), indexY);
			indexX -= tableSize;
			indexY -= tableSize;
			valueX = AdvSimd.Arm64.VectorTableLookupExtension(valueX, (s12, s13, s14, s15), indexX);
			valueY = AdvSimd.Arm64.VectorTableLookupExtension(valueY, (s12, s13, s14, s15), indexY);

			Vector128<uint> nextX = x0 ^ SM4Linear.Transform(valueX.AsUInt32());
			Vector128<uint> nextY = y0 ^ SM4Linear.Transform(valueY.AsUInt32());
			x0 = x1;
			y0 = y1;
			x1 = x2;
			y1 = y2;
			x2 = x3;
			y2 = y3;
			x3 = nextX;
			y3 = nextY;
		}

		SM4Layout.Store4Arm64(ref destination, x3, x2, x1, x0);
		SM4Layout.Store4Arm64(ref Unsafe.Add(ref destination, 64), y3, y2, y1, y0);
	}
}
