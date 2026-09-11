using static CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm.GHashSoftware;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm;

internal struct GHashEightBitState
{
	private InlineArray256<ulong> _hh;
	private InlineArray256<ulong> _hl;
	private VectorBuffer16 _accumulator;

	internal void Initialize(in VectorBuffer16 key, in VectorBuffer16 accumulator)
	{
		_accumulator = accumulator;

		ReadOnlySpan<byte> keyBytes = key;
		ulong vh = BinaryPrimitives.ReadUInt64BigEndian(keyBytes);
		ulong vl = BinaryPrimitives.ReadUInt64BigEndian(keyBytes.Slice(8));
		InitializeTable(vh, vl);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void GFMultiply(ref VectorBuffer16 accumulator, scoped ReadOnlySpan<byte> block)
	{
		accumulator ^= block.AsVectorBuffer16();

		ref byte buffer = ref Unsafe.As<VectorBuffer16, byte>(ref accumulator);
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

	internal void AppendPaddedSegment(scoped ReadOnlySpan<byte> source, ref VectorBuffer16 finalBlock)
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
		remaining.CopyTo(finalBlock);
		AppendBlocks(finalBlock);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void CopyAccumulatorTo(ref VectorBuffer16 destination)
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
