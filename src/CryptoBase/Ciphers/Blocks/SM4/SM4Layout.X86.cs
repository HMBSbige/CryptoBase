namespace CryptoBase.Ciphers.Blocks.SM4;

internal static partial class SM4Layout
{
	// Keep address formation inside count guards to avoid out-of-bounds byrefs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Load4X86(int count, ref byte source, nuint offset, out Vector128<byte> x0, out Vector128<byte> x1, out Vector128<byte> x2, out Vector128<byte> x3)
	{
		x0 = count > 0 ? Vector128.LoadUnsafe(ref source, offset).ReverseEndianness32() : Vector128<byte>.Zero;
		x1 = count > 1 ? Vector128.LoadUnsafe(ref source, offset + 16).ReverseEndianness32() : Vector128<byte>.Zero;
		x2 = count > 2 ? Vector128.LoadUnsafe(ref source, offset + 32).ReverseEndianness32() : Vector128<byte>.Zero;
		x3 = count > 3 ? Vector128.LoadUnsafe(ref source, offset + 48).ReverseEndianness32() : Vector128<byte>.Zero;
		Transpose(ref x0, ref x1, ref x2, ref x3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Store4X86(int count, ref byte destination, nuint offset, Vector128<byte> x0, Vector128<byte> x1, Vector128<byte> x2, Vector128<byte> x3)
	{
		Transpose(ref x0, ref x1, ref x2, ref x3);
		x0 = x0.ReverseEndianness128();
		x1 = x1.ReverseEndianness128();
		x2 = x2.ReverseEndianness128();
		x3 = x3.ReverseEndianness128();

		if (count > 0)
		{
			x0.StoreUnsafe(ref destination, offset);
		}

		if (count > 1)
		{
			x1.StoreUnsafe(ref destination, offset + 16);
		}

		if (count > 2)
		{
			x2.StoreUnsafe(ref destination, offset + 32);
		}

		if (count > 3)
		{
			x3.StoreUnsafe(ref destination, offset + 48);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Load8X86(int count, ref byte source, nuint offset, out Vector256<byte> x0, out Vector256<byte> x1, out Vector256<byte> x2, out Vector256<byte> x3)
	{
		x0 = count > 0 ? LoadPairX86(count, ref source, offset).ReverseEndianness32() : Vector256<byte>.Zero;
		x1 = count > 2 ? LoadPairX86(count - 2, ref source, offset + 32).ReverseEndianness32() : Vector256<byte>.Zero;
		x2 = count > 4 ? LoadPairX86(count - 4, ref source, offset + 64).ReverseEndianness32() : Vector256<byte>.Zero;
		x3 = count > 6 ? LoadPairX86(count - 6, ref source, offset + 96).ReverseEndianness32() : Vector256<byte>.Zero;
		Transpose(ref x0, ref x1, ref x2, ref x3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Store8X86(int count, ref byte destination, nuint offset, Vector256<byte> x0, Vector256<byte> x1, Vector256<byte> x2, Vector256<byte> x3)
	{
		Transpose(ref x0, ref x1, ref x2, ref x3);
		x0 = x0.ReverseEndianness128();
		x1 = x1.ReverseEndianness128();
		x2 = x2.ReverseEndianness128();
		x3 = x3.ReverseEndianness128();

		if (count > 0)
		{
			StorePairX86(count, ref destination, offset, x0);
		}

		if (count > 2)
		{
			StorePairX86(count - 2, ref destination, offset + 32, x1);
		}

		if (count > 4)
		{
			StorePairX86(count - 4, ref destination, offset + 64, x2);
		}

		if (count > 6)
		{
			StorePairX86(count - 6, ref destination, offset + 96, x3);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> LoadPairX86(int count, ref byte source, nuint offset)
	{
		if (count >= 2)
		{
			return Vector256.LoadUnsafe(ref source, offset);
		}

		return Vector256.Create(Vector128.LoadUnsafe(ref source, offset), Vector128<byte>.Zero);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StorePairX86(int count, ref byte destination, nuint offset, Vector256<byte> value)
	{
		if (count >= 2)
		{
			value.StoreUnsafe(ref destination, offset);
			return;
		}

		value.GetLower().StoreUnsafe(ref destination, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose(ref Vector128<byte> x0, ref Vector128<byte> x1, ref Vector128<byte> x2, ref Vector128<byte> x3)
	{
		Vector128<ulong> t0 = Sse2.UnpackHigh(x0.AsUInt32(), x1.AsUInt32()).AsUInt64();
		x0 = Sse2.UnpackLow(x0.AsUInt32(), x1.AsUInt32()).AsByte();

		Vector128<ulong> t1 = Sse2.UnpackLow(x2.AsUInt32(), x3.AsUInt32()).AsUInt64();
		x2 = Sse2.UnpackHigh(x2.AsUInt32(), x3.AsUInt32()).AsByte();

		x1 = Sse2.UnpackHigh(x0.AsUInt64(), t1).AsByte();
		x0 = Sse2.UnpackLow(x0.AsUInt64(), t1).AsByte();

		x3 = Sse2.UnpackHigh(t0, x2.AsUInt64()).AsByte();
		x2 = Sse2.UnpackLow(t0, x2.AsUInt64()).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose(ref Vector256<byte> x0, ref Vector256<byte> x1, ref Vector256<byte> x2, ref Vector256<byte> x3)
	{
		Vector256<ulong> t0 = Avx2.UnpackHigh(x0.AsUInt32(), x1.AsUInt32()).AsUInt64();
		x0 = Avx2.UnpackLow(x0.AsUInt32(), x1.AsUInt32()).AsByte();

		Vector256<ulong> t1 = Avx2.UnpackLow(x2.AsUInt32(), x3.AsUInt32()).AsUInt64();
		x2 = Avx2.UnpackHigh(x2.AsUInt32(), x3.AsUInt32()).AsByte();

		x1 = Avx2.UnpackHigh(x0.AsUInt64(), t1).AsByte();
		x0 = Avx2.UnpackLow(x0.AsUInt64(), t1).AsByte();

		x3 = Avx2.UnpackHigh(t0, x2.AsUInt64()).AsByte();
		x2 = Avx2.UnpackLow(t0, x2.AsUInt64()).AsByte();
	}
}
