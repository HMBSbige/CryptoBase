using static CryptoBase.Ciphers.Modes.Gcm.GHashSoftware;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashEightBitState
{
	private InlineArray256<ulong> _hh;
	private InlineArray256<ulong> _hl;
	private Vector128<byte> _accumulator;

	internal void Initialize(in Vector128<byte> key, in Vector128<byte> accumulator)
	{
		_accumulator = accumulator;

		ReadOnlySpan<byte> keyBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(in key, 1));
		ulong vh = BinaryPrimitives.ReadUInt64BigEndian(keyBytes);
		ulong vl = BinaryPrimitives.ReadUInt64BigEndian(keyBytes.Slice(8));
		InitializeTable(vh, vl);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void GFMultiply(ref Vector128<byte> accumulator, ref byte block)
	{
		accumulator ^= Vector128.LoadUnsafe(ref block);

		ref byte buffer = ref Unsafe.As<Vector128<byte>, byte>(ref accumulator);
		ref ulong hh = ref _hh[0];
		ref ulong hl = ref _hl[0];
		ref ulong reduction8 = ref Reduction8.GetReference();

		byte value = Unsafe.Add(ref buffer, GHash.BlockSizeInBytes - 1);
		ulong zh = Unsafe.Add(ref hh, value);
		ulong zl = Unsafe.Add(ref hl, value);

		for (int offset = GHash.BlockSizeInBytes - 2; offset >= 0; --offset)
		{
			value = Unsafe.Add(ref buffer, offset);
			byte rem = (byte)zl;
			zl = zh << 56 | zl >> 8;
			zh >>= 8;
			zh ^= Unsafe.Add(ref reduction8, rem);
			zh ^= Unsafe.Add(ref hh, value);
			zl ^= Unsafe.Add(ref hl, value);
		}

		if (BitConverter.IsLittleEndian)
		{
			zh = BinaryPrimitives.ReverseEndianness(zh);
			zl = BinaryPrimitives.ReverseEndianness(zl);
		}

		Unsafe.WriteUnaligned(ref buffer, zh);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref buffer, sizeof(ulong)), zl);
	}

	private void AppendBlocks(scoped ReadOnlySpan<byte> source)
	{
		ref byte input = ref source.GetReference();

		for (int remaining = source.Length; remaining > 0; remaining -= GHash.BlockSizeInBytes)
		{
			GFMultiply(ref _accumulator, ref input);
			input = ref Unsafe.Add(ref input, GHash.BlockSizeInBytes);
		}
	}

	internal void AppendPaddedSegment(scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
	{
		int completeLength = source.Length & -GHash.BlockSizeInBytes;

		if (completeLength is not 0)
		{
			AppendBlocks(source.Slice(0, completeLength));
		}

		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			return;
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());
		AppendBlocks(finalBlock.AsReadOnlySpan());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void CopyAccumulatorTo(ref Vector128<byte> destination)
	{
		destination = _accumulator;
	}

	private void InitializeTable(ulong vh, ulong vl)
	{
		GHashSoftware.InitializeTable(ref _hh[0], ref _hl[0], vh, vl, 128);
	}
}
