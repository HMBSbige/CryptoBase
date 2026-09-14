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
	private void GFMultiply(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> block)
	{
		accumulator ^= Vector128.LoadUnsafe(ref block.GetReference());

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
		ref ulong hh = ref _hh[0];
		ref ulong hl = ref _hl[0];

		hh = 0;
		hl = 0;
		Unsafe.Add(ref hl, 128) = vl;
		Unsafe.Add(ref hh, 128) = vh;

		int i = 64;

		while (i > 0)
		{
			ulong t = (vl & 1) * 0xe1000000;
			vl = vh << 63 | vl >> 1;
			vh = vh >> 1 ^ t << 32;

			Unsafe.Add(ref hl, i) = vl;
			Unsafe.Add(ref hh, i) = vh;
			i >>= 1;
		}

		i = 2;

		while (i <= 128)
		{
			vh = Unsafe.Add(ref hh, i);
			vl = Unsafe.Add(ref hl, i);

			for (int j = 1; j < i; ++j)
			{
				Unsafe.Add(ref hh, i + j) = vh ^ Unsafe.Add(ref hh, j);
				Unsafe.Add(ref hl, i + j) = vl ^ Unsafe.Add(ref hl, j);
			}

			i <<= 1;
		}
	}
}
