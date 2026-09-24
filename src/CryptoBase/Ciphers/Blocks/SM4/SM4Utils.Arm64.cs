namespace CryptoBase.Ciphers.Blocks.SM4;

internal static partial class SM4Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void Load4Arm64(ref byte source, out Vector128<uint> x0, out Vector128<uint> x1, out Vector128<uint> x2, out Vector128<uint> x3)
	{
		fixed (byte* address = &source)
		{
			(x0, x1, x2, x3) = AdvSimd.Arm64.Load4xVector128AndUnzip((uint*)address);
		}

		x0 = x0.ReverseEndianness32();
		x1 = x1.ReverseEndianness32();
		x2 = x2.ReverseEndianness32();
		x3 = x3.ReverseEndianness32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void Store4Arm64(ref byte destination, Vector128<uint> x0, Vector128<uint> x1, Vector128<uint> x2, Vector128<uint> x3)
	{
		fixed (byte* address = &destination)
		{
			AdvSimd.Arm64.StoreVectorAndZip((uint*)address, (x0.ReverseEndianness32(), x1.ReverseEndianness32(), x2.ReverseEndianness32(), x3.ReverseEndianness32()));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> LinearArm64(Vector128<uint> x)
	{
		Vector128<uint> r8 = x.RotateLeftUInt32(8);
		Vector128<uint> t = x ^ r8 ^ x.RotateLeftUInt32(16);
		Vector128<uint> r24 = x.RotateLeftUInt32(24);
		return x ^ t.RotateLeftUInt32(2) ^ r24;
	}
}
