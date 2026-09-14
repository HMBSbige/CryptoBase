namespace CryptoBase.Ciphers.Blocks.Aes;

internal partial struct AesCipherSoftware
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Load(ref InlineArray8<ulong> state, ref byte source, int length)
	{
		// Keep lane indices constant to eliminate bounds checks.
		LoadBlock(MemoryMarshal.CreateReadOnlySpan(ref source, 16), out state[0], out state[4]);

		if (length >= 32)
		{
			LoadBlock(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref source, 16), 16), out state[1], out state[5]);
		}

		if (length >= 48)
		{
			LoadBlock(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref source, 32), 16), out state[2], out state[6]);
		}

		if (length >= 64)
		{
			LoadBlock(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref source, 48), 16), out state[3], out state[7]);
		}

		Transpose(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadBlock(ReadOnlySpan<byte> source, out ulong low, out ulong high)
	{
		low = Interleave(BinaryPrimitives.ReadUInt32LittleEndian(source), BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(8)));
		high = Interleave(BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(4)), BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(12)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store(ref InlineArray8<ulong> state, ref byte destination, int length)
	{
		Transpose(ref state);
		StoreBlock(state[0], state[4], MemoryMarshal.CreateSpan(ref destination, 16));

		if (length >= 32)
		{
			StoreBlock(state[1], state[5], MemoryMarshal.CreateSpan(ref Unsafe.Add(ref destination, 16), 16));
		}

		if (length >= 48)
		{
			StoreBlock(state[2], state[6], MemoryMarshal.CreateSpan(ref Unsafe.Add(ref destination, 32), 16));
		}

		if (length >= 64)
		{
			StoreBlock(state[3], state[7], MemoryMarshal.CreateSpan(ref Unsafe.Add(ref destination, 48), 16));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreBlock(ulong low, ulong high, Span<byte> destination)
	{
		Deinterleave(low, out uint w0, out uint w2);
		Deinterleave(high, out uint w1, out uint w3);
		BinaryPrimitives.WriteUInt32LittleEndian(destination, w0);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(4), w1);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(8), w2);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12), w3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Interleave(uint low, uint high)
	{
		if (Bmi2.X64.IsSupported)
		{
			return Bmi2.X64.ParallelBitDeposit(low, 0x00FF00FF00FF00FF) | Bmi2.X64.ParallelBitDeposit(high, 0xFF00FF00FF00FF00);
		}

		ulong value = low | (ulong)high << 32;
		value = DeltaSwap(value, 16, 0x00000000FFFF0000);
		return DeltaSwap(value, 8, 0x0000FF000000FF00);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Deinterleave(ulong value, out uint low, out uint high)
	{
		if (Bmi2.X64.IsSupported)
		{
			low = (uint)Bmi2.X64.ParallelBitExtract(value, 0x00FF00FF00FF00FF);
			high = (uint)Bmi2.X64.ParallelBitExtract(value, 0xFF00FF00FF00FF00);
			return;
		}

		value = DeltaSwap(value, 8, 0x0000FF000000FF00);
		value = DeltaSwap(value, 16, 0x00000000FFFF0000);
		low = (uint)value;
		high = (uint)(value >> 32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose(ref InlineArray8<ulong> state)
	{
		ulong q0 = state[0];
		ulong q1 = state[1];
		ulong q2 = state[2];
		ulong q3 = state[3];
		ulong q4 = state[4];
		ulong q5 = state[5];
		ulong q6 = state[6];
		ulong q7 = state[7];

		Swap(ref q1, ref q0, 1, 0x5555555555555555);
		Swap(ref q3, ref q2, 1, 0x5555555555555555);
		Swap(ref q5, ref q4, 1, 0x5555555555555555);
		Swap(ref q7, ref q6, 1, 0x5555555555555555);
		Swap(ref q2, ref q0, 2, 0x3333333333333333);
		Swap(ref q3, ref q1, 2, 0x3333333333333333);
		Swap(ref q6, ref q4, 2, 0x3333333333333333);
		Swap(ref q7, ref q5, 2, 0x3333333333333333);
		Swap(ref q4, ref q0, 4, 0x0F0F0F0F0F0F0F0F);
		Swap(ref q5, ref q1, 4, 0x0F0F0F0F0F0F0F0F);
		Swap(ref q6, ref q2, 4, 0x0F0F0F0F0F0F0F0F);
		Swap(ref q7, ref q3, 4, 0x0F0F0F0F0F0F0F0F);

		state[0] = q0;
		state[1] = q1;
		state[2] = q2;
		state[3] = q3;
		state[4] = q4;
		state[5] = q5;
		state[6] = q6;
		state[7] = q7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Swap(ref ulong low, ref ulong high, int shift, ulong mask)
	{
		ulong delta = (low ^ high >> shift) & mask;
		low ^= delta;
		high ^= delta << shift;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong DeltaSwap(ulong value, int shift, ulong mask)
	{
		ulong delta = (value ^ value >> shift) & mask;
		return value ^ delta ^ delta << shift;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ShiftRowsTwo(ref InlineArray8<ulong> state)
	{
		state[0] = DeltaSwap(state[0], 8, 0x00FF000000FF0000);
		state[1] = DeltaSwap(state[1], 8, 0x00FF000000FF0000);
		state[2] = DeltaSwap(state[2], 8, 0x00FF000000FF0000);
		state[3] = DeltaSwap(state[3], 8, 0x00FF000000FF0000);
		state[4] = DeltaSwap(state[4], 8, 0x00FF000000FF0000);
		state[5] = DeltaSwap(state[5], 8, 0x00FF000000FF0000);
		state[6] = DeltaSwap(state[6], 8, 0x00FF000000FF0000);
		state[7] = DeltaSwap(state[7], 8, 0x00FF000000FF0000);
	}

	private static void ShiftRows(ref InlineArray8<ulong> state, int rows)
	{
		for (int i = 0; i < 8; ++i)
		{
			ulong value = state[i];

			switch (rows)
			{
				case 1:
				{
					value = DeltaSwap(value, 8, 0x00F000FF000F0000);
					value = DeltaSwap(value, 4, 0x0F0F00000F0F0000);
					break;
				}
				case 2:
				{
					value = DeltaSwap(value, 8, 0x00FF000000FF0000);
					break;
				}
				case 3:
				{
					value = DeltaSwap(value, 8, 0x000F00FF00F00000);
					value = DeltaSwap(value, 4, 0x0F0F00000F0F0000);
					break;
				}
			}

			state[i] = value;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateRows(ulong value, int columns)
	{
		return columns switch
		{
			0 => value.RotateRight(16),
			1 => RotateRowsMasked(value, 20, 4, 0x0FFF0FFF0FFF0FFF),
			2 => RotateRowsMasked(value, 24, 8, 0x00FF00FF00FF00FF),
			_ => RotateRowsMasked(value, 28, 12, 0x000F000F000F000F)
		};
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateRowsTwice(ulong value, int columns)
	{
		return (columns & 1) is 0 ? value.RotateRight(32) : RotateRowsMasked(value, 40, 24, 0x00FF00FF00FF00FF);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateRowsMasked(ulong value, int lowRotation, int highRotation, ulong mask)
	{
		ulong high = value.RotateRight(highRotation);
		return high ^ (value.RotateRight(lowRotation) ^ high) & mask;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static InlineArray8<ulong> MixColumns(InlineArray8<ulong> state, in InlineArray8<ulong> key, int columns)
	{
		// Finish each plane early to reduce register pressure.
		ulong r7 = RotateRows(state[7], columns);
		ulong c7 = state[7] ^ r7;

		ulong r0 = RotateRows(state[0], columns);
		ulong c0 = state[0] ^ r0;
		state[0] = r0 ^ c7 ^ RotateRowsTwice(c0, columns) ^ key[0];

		ulong r1 = RotateRows(state[1], columns);
		ulong c1 = state[1] ^ r1;
		state[1] = r1 ^ c0 ^ c7 ^ RotateRowsTwice(c1, columns) ^ key[1];

		ulong r2 = RotateRows(state[2], columns);
		ulong c2 = state[2] ^ r2;
		state[2] = r2 ^ c1 ^ RotateRowsTwice(c2, columns) ^ key[2];

		ulong r3 = RotateRows(state[3], columns);
		ulong c3 = state[3] ^ r3;
		state[3] = r3 ^ c2 ^ c7 ^ RotateRowsTwice(c3, columns) ^ key[3];

		ulong r4 = RotateRows(state[4], columns);
		ulong c4 = state[4] ^ r4;
		state[4] = r4 ^ c3 ^ c7 ^ RotateRowsTwice(c4, columns) ^ key[4];

		ulong r5 = RotateRows(state[5], columns);
		ulong c5 = state[5] ^ r5;
		state[5] = r5 ^ c4 ^ RotateRowsTwice(c5, columns) ^ key[5];

		ulong r6 = RotateRows(state[6], columns);
		ulong c6 = state[6] ^ r6;
		state[6] = r6 ^ c5 ^ RotateRowsTwice(c6, columns) ^ key[6];

		state[7] = r7 ^ c6 ^ RotateRowsTwice(c7, columns) ^ key[7];
		return state;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static InlineArray8<ulong> InverseMixColumns(in InlineArray8<ulong> input, in InlineArray8<ulong> key, int columns)
	{
		InlineArray8<ulong> state = default;
		ulong a0 = input[0] ^ key[0];
		ulong a1 = input[1] ^ key[1];
		ulong a2 = input[2] ^ key[2];
		ulong a3 = input[3] ^ key[3];
		ulong a4 = input[4] ^ key[4];
		ulong a5 = input[5] ^ key[5];
		ulong a6 = input[6] ^ key[6];
		ulong a7 = input[7] ^ key[7];

		ulong c0 = a0 ^ RotateRows(a0, columns);
		ulong c1 = a1 ^ RotateRows(a1, columns);
		ulong c2 = a2 ^ RotateRows(a2, columns);
		ulong c3 = a3 ^ RotateRows(a3, columns);
		ulong c4 = a4 ^ RotateRows(a4, columns);
		ulong c5 = a5 ^ RotateRows(a5, columns);
		ulong c6 = a6 ^ RotateRows(a6, columns);
		ulong c7 = a7 ^ RotateRows(a7, columns);

		ulong d0 = a0 ^ c7;
		ulong d1 = a1 ^ c0 ^ c7;
		ulong d2 = a2 ^ c1;
		ulong d3 = a3 ^ c2 ^ c7;
		ulong d4 = a4 ^ c3 ^ c7;
		ulong d5 = a5 ^ c4;
		ulong d6 = a6 ^ c5;
		ulong d7 = a7 ^ c6;

		ulong d67 = d6 ^ d7;

		ulong e = c0 ^ d6;
		state[0] = d0 ^ e ^ RotateRowsTwice(e, columns);
		e = c1 ^ d67;
		state[1] = d1 ^ e ^ RotateRowsTwice(e, columns);
		e = c2 ^ d0 ^ d7;
		state[2] = d2 ^ e ^ RotateRowsTwice(e, columns);
		e = c3 ^ d1 ^ d6;
		state[3] = d3 ^ e ^ RotateRowsTwice(e, columns);
		e = c4 ^ d2 ^ d67;
		state[4] = d4 ^ e ^ RotateRowsTwice(e, columns);
		e = c5 ^ d3 ^ d7;
		state[5] = d5 ^ e ^ RotateRowsTwice(e, columns);
		e = c6 ^ d4;
		state[6] = d6 ^ e ^ RotateRowsTwice(e, columns);
		e = c7 ^ d5;
		state[7] = d7 ^ e ^ RotateRowsTwice(e, columns);
		return state;
	}
}
