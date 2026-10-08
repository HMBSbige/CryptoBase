using static CryptoBase.Hashes.Blake2b.Blake2bCore;

namespace CryptoBase.Hashes.Blake2b;

internal readonly struct Blake2bScalar : IBlake2bKernel
{
	public static bool IsSupported => true;

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Compress(ref ulong state, ReadOnlySpan<byte> blocks, UInt128 counter, ulong finalFlag)
	{
		Debug.Assert(!blocks.IsEmpty && blocks.Length % BlockSizeInBytes is 0);

		ref byte block = ref blocks.GetReference();
		nuint remainingBlocks = (uint)blocks.Length / BlockSizeInBytes;
		ulong counterLow = (ulong)counter;
		ulong counterHigh = (ulong)(counter >> 64);

		do
		{
			ulong v0 = state;
			ulong v1 = Unsafe.Add(ref state, 1);
			ulong v2 = Unsafe.Add(ref state, 2);
			ulong v3 = Unsafe.Add(ref state, 3);
			ulong v4 = Unsafe.Add(ref state, 4);
			ulong v5 = Unsafe.Add(ref state, 5);
			ulong v6 = Unsafe.Add(ref state, 6);
			ulong v7 = Unsafe.Add(ref state, 7);
			ulong v8 = IV0;
			ulong v9 = IV1;
			ulong v10 = IV2;
			ulong v11 = IV3;
			ulong v12 = IV4 ^ counterLow;
			ulong v13 = IV5 ^ counterHigh;
			ulong v14 = IV6 ^ finalFlag;
			ulong v15 = IV7;

			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 14, 8, 10, 12, 15, 9, 11, 13);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 14, 4, 9, 13, 10, 8, 15, 6);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 5, 1, 0, 11, 3, 12, 2, 7);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 11, 12, 5, 15, 8, 0, 2, 13);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 9, 10, 3, 7, 4, 14, 6, 1);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 7, 3, 13, 11, 9, 1, 12, 14);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 15, 2, 5, 4, 8, 6, 10, 0);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 9, 5, 2, 10, 0, 7, 4, 15);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 3, 14, 11, 6, 13, 1, 12, 8);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 2, 6, 0, 8, 12, 10, 11, 3);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 1, 4, 7, 15, 9, 13, 5, 14);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 12, 1, 14, 4, 5, 15, 13, 10);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 8, 0, 6, 9, 11, 7, 3, 2);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 13, 7, 12, 3, 11, 14, 1, 9);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 2, 5, 15, 8, 10, 0, 4, 6);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 6, 14, 11, 0, 15, 9, 3, 8);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 10, 12, 13, 1, 5, 2, 7, 4);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 10, 8, 7, 1, 2, 4, 6, 5);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 13, 15, 9, 3, 0, 11, 14, 12);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 14, 8, 10, 12, 15, 9, 11, 13);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 14, 4, 9, 13, 10, 8, 15, 6);
			Step(ref v3, ref v0, ref v1, ref v2, ref v4, ref v5, ref v6, ref v7, ref v9, ref v10, ref v11, ref v8, ref v14, ref v15, ref v12, ref v13, ref block, 5, 1, 0, 11, 3, 12, 2, 7);

			state ^= v0 ^ v8;
			Unsafe.Add(ref state, 1) ^= v1 ^ v9;
			Unsafe.Add(ref state, 2) ^= v2 ^ v10;
			Unsafe.Add(ref state, 3) ^= v3 ^ v11;
			Unsafe.Add(ref state, 4) ^= v4 ^ v12;
			Unsafe.Add(ref state, 5) ^= v5 ^ v13;
			Unsafe.Add(ref state, 6) ^= v6 ^ v14;
			Unsafe.Add(ref state, 7) ^= v7 ^ v15;

			counterLow += BlockSizeInBytes;
			counterHigh += counterLow < BlockSizeInBytes ? 1UL : 0UL;
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
		} while (--remainingBlocks is not 0);
	}

	// Runs G on four lanes in lockstep, which is faster than running the lanes one after another.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step(ref ulong a0, ref ulong a1, ref ulong a2, ref ulong a3, ref ulong b0, ref ulong b1, ref ulong b2, ref ulong b3, ref ulong c0, ref ulong c1, ref ulong c2, ref ulong c3, ref ulong d0, ref ulong d1, ref ulong d2, ref ulong d3, ref byte block, int x0, int x1, int x2, int x3, int y0, int y1, int y2, int y3)
	{
		// Adding the message word first keeps one addition off the b dependency chain.
		a0 = a0 + MessageWord(ref block, x0) + b0;
		a1 = a1 + MessageWord(ref block, x1) + b1;
		a2 = a2 + MessageWord(ref block, x2) + b2;
		a3 = a3 + MessageWord(ref block, x3) + b3;
		d0 = BitOperations.RotateRight(d0 ^ a0, 32);
		d1 = BitOperations.RotateRight(d1 ^ a1, 32);
		d2 = BitOperations.RotateRight(d2 ^ a2, 32);
		d3 = BitOperations.RotateRight(d3 ^ a3, 32);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = BitOperations.RotateRight(b0 ^ c0, 24);
		b1 = BitOperations.RotateRight(b1 ^ c1, 24);
		b2 = BitOperations.RotateRight(b2 ^ c2, 24);
		b3 = BitOperations.RotateRight(b3 ^ c3, 24);
		a0 = a0 + MessageWord(ref block, y0) + b0;
		a1 = a1 + MessageWord(ref block, y1) + b1;
		a2 = a2 + MessageWord(ref block, y2) + b2;
		a3 = a3 + MessageWord(ref block, y3) + b3;
		d0 = BitOperations.RotateRight(d0 ^ a0, 16);
		d1 = BitOperations.RotateRight(d1 ^ a1, 16);
		d2 = BitOperations.RotateRight(d2 ^ a2, 16);
		d3 = BitOperations.RotateRight(d3 ^ a3, 16);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = BitOperations.RotateRight(b0 ^ c0, 63);
		b1 = BitOperations.RotateRight(b1 ^ c1, 63);
		b2 = BitOperations.RotateRight(b2 ^ c2, 63);
		b3 = BitOperations.RotateRight(b3 ^ c3, 63);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong MessageWord(ref byte block, int index)
	{
		ulong word = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, index * sizeof(ulong)));
		return BitConverter.IsLittleEndian ? word : BinaryPrimitives.ReverseEndianness(word);
	}
}
