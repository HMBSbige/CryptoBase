using System.Numerics;

namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	private const int Pack5FastOverReadBytes = sizeof(ulong) - InputBytesPerBlock;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Pack5(ref byte source)
	{
		return (ulong)source << 32
				| (ulong)Unsafe.Add(ref source, 1) << 24
				| (ulong)Unsafe.Add(ref source, 2) << 16
				| (ulong)Unsafe.Add(ref source, 3) << 8
				| Unsafe.Add(ref source, 4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Pack5Fast(ref byte source)
	{
		return BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref source)) >> 24;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncodeBlock(ref byte source, ref char destination, ref byte alphabet)
	{
		ulong value = Pack5(ref source);
		Unsafe.Add(ref destination, 0) = (char)Unsafe.Add(ref alphabet, (int)(value >> 35 & SymbolMask));
		Unsafe.Add(ref destination, 1) = (char)Unsafe.Add(ref alphabet, (int)(value >> 30 & SymbolMask));
		Unsafe.Add(ref destination, 2) = (char)Unsafe.Add(ref alphabet, (int)(value >> 25 & SymbolMask));
		Unsafe.Add(ref destination, 3) = (char)Unsafe.Add(ref alphabet, (int)(value >> 20 & SymbolMask));
		Unsafe.Add(ref destination, 4) = (char)Unsafe.Add(ref alphabet, (int)(value >> 15 & SymbolMask));
		Unsafe.Add(ref destination, 5) = (char)Unsafe.Add(ref alphabet, (int)(value >> 10 & SymbolMask));
		Unsafe.Add(ref destination, 6) = (char)Unsafe.Add(ref alphabet, (int)(value >> 5 & SymbolMask));
		Unsafe.Add(ref destination, 7) = (char)Unsafe.Add(ref alphabet, (int)(value & SymbolMask));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncodePackedBlock(ulong value, ref byte destination, ref byte alphabet)
	{
		Unsafe.Add(ref destination, 0) = Unsafe.Add(ref alphabet, (int)(value >> 35 & SymbolMask));
		Unsafe.Add(ref destination, 1) = Unsafe.Add(ref alphabet, (int)(value >> 30 & SymbolMask));
		Unsafe.Add(ref destination, 2) = Unsafe.Add(ref alphabet, (int)(value >> 25 & SymbolMask));
		Unsafe.Add(ref destination, 3) = Unsafe.Add(ref alphabet, (int)(value >> 20 & SymbolMask));
		Unsafe.Add(ref destination, 4) = Unsafe.Add(ref alphabet, (int)(value >> 15 & SymbolMask));
		Unsafe.Add(ref destination, 5) = Unsafe.Add(ref alphabet, (int)(value >> 10 & SymbolMask));
		Unsafe.Add(ref destination, 6) = Unsafe.Add(ref alphabet, (int)(value >> 5 & SymbolMask));
		Unsafe.Add(ref destination, 7) = Unsafe.Add(ref alphabet, (int)(value & SymbolMask));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncodeBlock(ref byte source, ref byte destination, ref byte alphabet)
	{
		EncodePackedBlock(Pack5(ref source), ref destination, ref alphabet);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EncodeTail<T>(ReadOnlySpan<byte> source, Span<T> destination) where T : unmanaged, INumberBase<T>
	{
		uint value = 0;

		switch (source.Length)
		{
			case 4:
			{
				value |= source[3];
				destination[6] = T.CreateChecked(_alphabet[(int)(value << 3 & SymbolMask)]);
				destination[5] = T.CreateChecked(_alphabet[(int)(value >> 2 & SymbolMask)]);
				goto case 3;
			}
			case 3:
			{
				value |= (uint)source[2] << 8;
				destination[4] = T.CreateChecked(_alphabet[(int)(value >> 7 & SymbolMask)]);
				goto case 2;
			}
			case 2:
			{
				value |= (uint)source[1] << 16;
				destination[3] = T.CreateChecked(_alphabet[(int)(value >> 12 & SymbolMask)]);
				destination[2] = T.CreateChecked(_alphabet[(int)(value >> 17 & SymbolMask)]);
				goto case 1;
			}
			case 1:
			{
				value |= (uint)source[0] << 24;
				destination[1] = T.CreateChecked(_alphabet[(int)(value >> 22 & SymbolMask)]);
				destination[0] = T.CreateChecked(_alphabet[(int)(value >> 27 & SymbolMask)]);
				break;
			}
		}
	}

	private int DecodeScalar<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength) where T : unmanaged
	{
		int blockCount = Math.Min(fullLength / OutputSymbolsPerBlock, destination.Length / InputBytesPerBlock);
		ref T sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		ref byte decodeTable = ref MemoryMarshal.GetArrayDataReference(_decodeTable);
		int processedBlocks = 0;

		for (; processedBlocks < blockCount; ++processedBlocks)
		{
			if (!TryDecodeBlock(ref sourcePointer, ref destinationPointer, ref decodeTable))
			{
				break;
			}

			sourcePointer = ref Unsafe.Add(ref sourcePointer, OutputSymbolsPerBlock);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, InputBytesPerBlock);
		}

		return processedBlocks * OutputSymbolsPerBlock;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecodeBlock(ref char source, ref byte destination, ref byte decodeTable)
	{
		uint s0 = source;
		uint s1 = Unsafe.Add(ref source, 1);
		uint s2 = Unsafe.Add(ref source, 2);
		uint s3 = Unsafe.Add(ref source, 3);
		uint s4 = Unsafe.Add(ref source, 4);
		uint s5 = Unsafe.Add(ref source, 5);
		uint s6 = Unsafe.Add(ref source, 6);
		uint s7 = Unsafe.Add(ref source, 7);

		if ((s0 | s1 | s2 | s3 | s4 | s5 | s6 | s7) > 0x7FU)
		{
			return false;
		}

		int v0 = Unsafe.Add(ref decodeTable, (int)s0);
		int v1 = Unsafe.Add(ref decodeTable, (int)s1);
		int v2 = Unsafe.Add(ref decodeTable, (int)s2);
		int v3 = Unsafe.Add(ref decodeTable, (int)s3);
		int v4 = Unsafe.Add(ref decodeTable, (int)s4);
		int v5 = Unsafe.Add(ref decodeTable, (int)s5);
		int v6 = Unsafe.Add(ref decodeTable, (int)s6);
		int v7 = Unsafe.Add(ref decodeTable, (int)s7);

		if ((v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) is InvalidSymbol)
		{
			return false;
		}

		WriteDecodedBlock(ref destination, v0, v1, v2, v3, v4, v5, v6, v7);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecodeBlock(ref byte source, ref byte destination, ref byte decodeTable)
	{
		int v0 = Unsafe.Add(ref decodeTable, source);
		int v1 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 1));
		int v2 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 2));
		int v3 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 3));
		int v4 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 4));
		int v5 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 5));
		int v6 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 6));
		int v7 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 7));

		if ((v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) > SymbolMask)
		{
			return false;
		}

		WriteDecodedBlock(ref destination, v0, v1, v2, v3, v4, v5, v6, v7);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryDecodeBlock<T>(ReadOnlySpan<T> source, int sourceOffset, Span<byte> destination, int destinationOffset) where T : unmanaged
	{
		ref T sourceReference = ref Unsafe.Add(ref source.GetReference(), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref destination.GetReference(), destinationOffset);
		ref byte decodeTableReference = ref MemoryMarshal.GetArrayDataReference(_decodeTable);
		return TryDecodeBlock(ref sourceReference, ref destinationReference, ref decodeTableReference);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecodeBlock<T>(ref T source, ref byte destination, ref byte decodeTable) where T : unmanaged
	{
		return typeof(T) == typeof(char)
			? TryDecodeBlock(ref Unsafe.As<T, char>(ref source), ref destination, ref decodeTable)
			: TryDecodeBlock(ref Unsafe.As<T, byte>(ref source), ref destination, ref decodeTable);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteDecodedBlock(ref byte destination, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7)
	{
		Unsafe.Add(ref destination, 0) = (byte)(v0 << 3 | v1 >> 2);
		Unsafe.Add(ref destination, 1) = (byte)(v1 << 6 | v2 << 1 | v3 >> 4);
		Unsafe.Add(ref destination, 2) = (byte)(v3 << 4 | v4 >> 1);
		Unsafe.Add(ref destination, 3) = (byte)(v4 << 7 | v5 << 2 | v6 >> 3);
		Unsafe.Add(ref destination, 4) = (byte)(v6 << 5 | v7);
	}

	private bool TryDecodeTail<T>(ReadOnlySpan<T> source, Span<byte> destination, out int symbolsConsumed, out int bytesWritten) where T : unmanaged, INumberBase<T>
	{
		int buffer = 0;
		int bits = 0;
		int destinationOffset = 0;

		for (int i = 0; i < source.Length; ++i)
		{
			if (!TryGetValue(source[i], out int value))
			{
				symbolsConsumed = i;
				bytesWritten = destinationOffset;
				return false;
			}

			buffer = buffer << 5 | value;
			bits += 5;

			if (bits >= 8)
			{
				bits -= 8;
				destination[destinationOffset++] = (byte)(buffer >> bits);
				buffer &= (1 << bits) - 1;
			}
		}

		symbolsConsumed = source.Length;
		bytesWritten = destinationOffset;
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryGetValue<T>(T symbol, out int value) where T : unmanaged, INumberBase<T>
	{
		int index = int.CreateChecked(symbol);
		byte[] decodeTable = _decodeTable;

		if ((uint)index >= (uint)decodeTable.Length)
		{
			value = InvalidSymbol;
			return false;
		}

		value = decodeTable[index];
		return value is not InvalidSymbol;
	}
}
