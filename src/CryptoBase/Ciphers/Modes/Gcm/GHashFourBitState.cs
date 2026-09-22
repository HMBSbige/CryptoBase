using static CryptoBase.Ciphers.Modes.Gcm.GHashSoftware;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashFourBitState
{
	private InlineArray16<ulong> _hh;
	private InlineArray16<ulong> _hl;
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
	private void GFMultiply(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> block)
	{
		accumulator ^= Vector128.LoadUnsafe(ref block.GetReference());

		ref byte buffer = ref Unsafe.As<Vector128<byte>, byte>(ref accumulator);
		ref ulong hh = ref _hh[0];
		ref ulong hl = ref _hl[0];
		ReadOnlySpan<ulong> reduction4 = Reduction4;

		byte value = Unsafe.Add(ref buffer, GHash.BlockSizeInBytes - 1);
		byte lo = (byte)(value & 0x0f);
		ulong zh = Unsafe.Add(ref hh, lo);
		ulong zl = Unsafe.Add(ref hl, lo);
		byte hi = (byte)(value >> 4);
		byte rem = (byte)(zl & 0x0f);
		zl = zh << 60 | zl >> 4;
		zh >>= 4;
		zh ^= reduction4[rem];
		zh ^= Unsafe.Add(ref hh, hi);
		zl ^= Unsafe.Add(ref hl, hi);

		for (int offset = GHash.BlockSizeInBytes - 2; offset >= 0; --offset)
		{
			value = Unsafe.Add(ref buffer, offset);
			lo = (byte)(value & 0x0f);
			rem = (byte)(zl & 0x0f);
			zl = zh << 60 | zl >> 4;
			zh >>= 4;
			zh ^= reduction4[rem];
			zh ^= Unsafe.Add(ref hh, lo);
			zl ^= Unsafe.Add(ref hl, lo);

			hi = (byte)(value >> 4);
			rem = (byte)(zl & 0x0f);
			zl = zh << 60 | zl >> 4;
			zh >>= 4;
			zh ^= reduction4[rem];
			zh ^= Unsafe.Add(ref hh, hi);
			zl ^= Unsafe.Add(ref hl, hi);
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
		while (!source.IsEmpty)
		{
			GFMultiply(ref _accumulator, source);
			source = source.Slice(GHash.BlockSizeInBytes);
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
		GHashSoftware.InitializeTable(ref _hh[0], ref _hl[0], vh, vl, 8);
	}
}
