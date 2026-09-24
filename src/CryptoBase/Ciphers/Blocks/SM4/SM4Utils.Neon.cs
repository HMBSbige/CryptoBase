namespace CryptoBase.Ciphers.Blocks.SM4;

internal static partial class SM4Utils
{
	public static unsafe void Process4Neon(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		Vector128<byte> tableSize = Vector128.Create((byte)64);
		Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		ref uint keys = ref rk.GetReference();

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> index = (x1 ^ x2 ^ x3 ^ Vector128.Create(Unsafe.Add(ref keys, i))).AsByte();
			Vector128<byte> value = AdvSimd.Arm64.VectorTableLookup((s0, s1, s2, s3), index);
			index -= tableSize;
			value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s4, s5, s6, s7), index);
			index -= tableSize;
			value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s8, s9, s10, s11), index);
			index -= tableSize;
			value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s12, s13, s14, s15), index);

			Vector128<uint> next = x0 ^ LinearArm64(value.AsUInt32());
			x0 = x1;
			x1 = x2;
			x2 = x3;
			x3 = next;
		}

		Store4Arm64(ref destination, x3, x2, x1, x0);
	}

	public static unsafe void Process8Neon(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		Vector128<byte> tableSize = Vector128.Create((byte)64);
		Load4Arm64(ref source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3);
		Load4Arm64(ref Unsafe.Add(ref source, 64), out Vector128<uint> y0, out Vector128<uint> y1, out Vector128<uint> y2, out Vector128<uint> y3);
		ref uint keys = ref rk.GetReference();

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

			Vector128<uint> nextX = x0 ^ LinearArm64(valueX.AsUInt32());
			Vector128<uint> nextY = y0 ^ LinearArm64(valueY.AsUInt32());
			x0 = x1;
			y0 = y1;
			x1 = x2;
			y1 = y2;
			x2 = x3;
			y2 = y3;
			x3 = nextX;
			y3 = nextY;
		}

		Store4Arm64(ref destination, x3, x2, x1, x0);
		Store4Arm64(ref Unsafe.Add(ref destination, 64), y3, y2, y1, y0);
	}
}
