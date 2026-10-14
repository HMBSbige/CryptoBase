using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal readonly partial struct Blake3Vector128 : IBlake3Compressor
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void CompressBlocks(ref uint cv, ref byte blocks, nuint blockCount, ulong counter, uint flags, uint startFlags, uint endFlags)
	{
		Debug.Assert(blockCount is not 0);

		Vector128<uint> h0 = Vector128.LoadUnsafe(ref cv);
		Vector128<uint> h1 = Vector128.LoadUnsafe(ref cv, 4);
		uint blockFlags = flags | startFlags;

		do
		{
			Vector128<uint> row0 = h0;
			Vector128<uint> row1 = h1;
			Vector128<uint> row2 = Vector128.Create(IV0, IV1, IV2, IV3);
			Vector128<uint> row3 = CreateRow3(counter, BlockLength, blockCount is 1 ? blockFlags | endFlags : blockFlags);

			Rounds(ref row0, ref row1, ref row2, ref row3, ref blocks);

			h0 = row0 ^ row2;
			h1 = row1 ^ row3;
			blockFlags = flags;
			blocks = ref Unsafe.Add(ref blocks, BlockLength);
		} while (--blockCount is not 0);

		h0.StoreUnsafe(ref cv);
		h1.StoreUnsafe(ref cv, 4);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Compress(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		Vector128<uint> row0 = Vector128.LoadUnsafe(in cv);
		Vector128<uint> row1 = Vector128.LoadUnsafe(in cv, 4);
		Vector128<uint> row2 = Vector128.Create(IV0, IV1, IV2, IV3);
		Vector128<uint> row3 = CreateRow3(counter, blockLength, flags);

		Rounds(ref row0, ref row1, ref row2, ref row3, ref block);

		(row0 ^ row2).AsByte().StoreUnsafe(ref output);
		(row1 ^ row3).AsByte().StoreUnsafe(ref output, 16);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void CompressXof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		Vector128<uint> h0 = Vector128.LoadUnsafe(in cv);
		Vector128<uint> h1 = Vector128.LoadUnsafe(in cv, 4);
		Vector128<uint> row0 = h0;
		Vector128<uint> row1 = h1;
		Vector128<uint> row2 = Vector128.Create(IV0, IV1, IV2, IV3);
		Vector128<uint> row3 = CreateRow3(counter, blockLength, flags);

		Rounds(ref row0, ref row1, ref row2, ref row3, ref block);

		(row0 ^ row2).AsByte().StoreUnsafe(ref output);
		(row1 ^ row3).AsByte().StoreUnsafe(ref output, 16);
		(row2 ^ h0).AsByte().StoreUnsafe(ref output, 32);
		(row3 ^ h1).AsByte().StoreUnsafe(ref output, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> CreateRow3(ulong counter, uint blockLength, uint flags)
	{
		return Vector128.CreateUInt64(counter, (ulong)flags << 32 | blockLength).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds(ref Vector128<uint> row0, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref byte block)
	{
		Vector128<uint> m0 = Vector128.LoadUnsafe(ref block).AsUInt32();
		Vector128<uint> m1 = Vector128.LoadUnsafe(ref block, 16).AsUInt32();
		Vector128<uint> m2 = Vector128.LoadUnsafe(ref block, 32).AsUInt32();
		Vector128<uint> m3 = Vector128.LoadUnsafe(ref block, 48).AsUInt32();

		Vector128<uint> x0 = UnzipEven(m0, m1);
		Vector128<uint> y0 = UnzipOdd(m0, m1);
		Vector128<uint> x1 = UnzipEven(m2, m3).RotateWordsLeft(3);
		Vector128<uint> y1 = UnzipOdd(m2, m3).RotateWordsLeft(3);
		Round(ref row0, ref row1, ref row2, ref row3, x0, y0, x1, y1);

		for (int round = 1; round < Blake3Constants.Rounds; ++round)
		{
			PermuteMessage(ref x0, ref y0, ref x1, ref y1);
			Round(ref row0, ref row1, ref row2, ref row3, x0, y0, x1, y1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector128<uint> row0, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, Vector128<uint> x0, Vector128<uint> y0, Vector128<uint> x1, Vector128<uint> y1)
	{
		G(ref row0, ref row1, ref row2, ref row3, x0, y0);

		// Rotating the rows around row1, the last one G writes, keeps the shuffles off its critical path.
		row0 = row0.RotateWordsLeft(3);
		row3 = row3.RotateWordsLeft(2);
		row2 = row2.RotateWordsLeft(1);

		G(ref row0, ref row1, ref row2, ref row3, x1, y1);

		row0 = row0.RotateWordsLeft(1);
		row3 = row3.RotateWordsLeft(2);
		row2 = row2.RotateWordsLeft(3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G(ref Vector128<uint> row0, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, Vector128<uint> x, Vector128<uint> y)
	{
		row0 = row0 + x + row1;
		row3 = (row3 ^ row0).RotateRightUInt32(16);
		row2 += row3;
		row1 = (row1 ^ row2).RotateRightUInt32(12);
		row0 = row0 + y + row1;
		row3 = (row3 ^ row0).RotateRightUInt32(8);
		row2 += row3;
		row1 = (row1 ^ row2).RotateRightUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermuteMessage(ref Vector128<uint> x0, ref Vector128<uint> y0, ref Vector128<uint> x1, ref Vector128<uint> y1)
	{
		if (AdvSimd.Arm64.IsSupported)
		{
			(Vector128<byte>, Vector128<byte>, Vector128<byte>, Vector128<byte>) words = (x0.AsByte(), y0.AsByte(), x1.AsByte(), y1.AsByte());
			x0 = AdvSimd.Arm64.VectorTableLookup((words.Item1, words.Item2), Vector128.Create((byte)4, 5, 6, 7, 20, 21, 22, 23, 28, 29, 30, 31, 8, 9, 10, 11)).AsUInt32();
			y0 = AdvSimd.Arm64.VectorTableLookup(words, Vector128.Create((byte)12, 13, 14, 15, 40, 41, 42, 43, 0, 1, 2, 3, 60, 61, 62, 63)).AsUInt32();
			x1 = AdvSimd.Arm64.VectorTableLookup(words, Vector128.Create((byte)48, 49, 50, 51, 16, 17, 18, 19, 44, 45, 46, 47, 52, 53, 54, 55)).AsUInt32();
			y1 = AdvSimd.Arm64.VectorTableLookup(words, Vector128.Create((byte)36, 37, 38, 39, 56, 57, 58, 59, 24, 25, 26, 27, 32, 33, 34, 35)).AsUInt32();
			return;
		}

		Vector128<uint> nextX0 = Sse2.Shuffle(Shuffle(x0, y0, 0b11_01_01_10), 0b00_11_10_01);
		Vector128<uint> nextY0 = BlendOddWords(Sse2.Shuffle(x0, 0b00_00_11_11), Shuffle(x1, y1, 0b11_11_10_10));
		Vector128<uint> nextX1 = Sse2.Shuffle(BlendLastWord(Sse2.UnpackLow(y1.AsUInt64(), y0.AsUInt64()).AsUInt32(), x1), 0b01_11_10_00);
		Vector128<uint> nextY1 = Sse2.Shuffle(Sse2.UnpackLow(x1, Sse2.UnpackHigh(y0, y1)), 0b00_01_11_10);
		x0 = nextX0;
		y0 = nextY0;
		x1 = nextX1;
		y1 = nextY1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UnzipEven(Vector128<uint> left, Vector128<uint> right)
	{
		return AdvSimd.Arm64.IsSupported ? AdvSimd.Arm64.UnzipEven(left, right) : Shuffle(left, right, 0b10_00_10_00);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UnzipOdd(Vector128<uint> left, Vector128<uint> right)
	{
		return AdvSimd.Arm64.IsSupported ? AdvSimd.Arm64.UnzipOdd(left, right) : Shuffle(left, right, 0b11_01_11_01);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Shuffle(Vector128<uint> left, Vector128<uint> right, [ConstantExpected] byte control)
	{
		return Sse.Shuffle(left.AsSingle(), right.AsSingle(), control).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> BlendOddWords(Vector128<uint> left, Vector128<uint> right)
	{
		if (Avx2.IsSupported)
		{
			return Avx2.Blend(left, right, 0b1010);
		}

		if (Sse41.IsSupported)
		{
			return Sse41.Blend(left.AsUInt16(), right.AsUInt16(), 0b11_00_11_00).AsUInt32();
		}

		return Vector128.ConditionalSelect(Vector128.Create(0u, ~0u, 0u, ~0u), right, left);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> BlendLastWord(Vector128<uint> left, Vector128<uint> right)
	{
		if (Avx2.IsSupported)
		{
			return Avx2.Blend(left, right, 0b1000);
		}

		if (Sse41.IsSupported)
		{
			return Sse41.Blend(left.AsUInt16(), right.AsUInt16(), 0b11_00_00_00).AsUInt32();
		}

		return Vector128.ConditionalSelect(Vector128.Create(0u, 0u, 0u, ~0u), right, left);
	}
}
