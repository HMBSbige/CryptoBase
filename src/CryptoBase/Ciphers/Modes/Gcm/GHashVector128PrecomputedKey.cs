using static CryptoBase.Ciphers.Modes.Gcm.GHashX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal readonly struct GHashVector128PrecomputedKey
{
	private readonly Vector128<byte> _key1;
	private readonly Vector128<byte> _keyK1;
	private readonly Vector128<byte> _key2;
	private readonly Vector128<byte> _keyK2;
	private readonly Vector128<byte> _key3;
	private readonly Vector128<byte> _keyK3;
	private readonly Vector128<byte> _key4;
	private readonly Vector128<byte> _keyK4;
	private readonly Vector128<byte> _key5;
	private readonly Vector128<byte> _keyK5;
	private readonly Vector128<byte> _key6;
	private readonly Vector128<byte> _keyK6;
	private readonly Vector128<byte> _key7;
	private readonly Vector128<byte> _keyK7;
	private readonly Vector128<byte> _key8;
	private readonly Vector128<byte> _keyK8;

	internal GHashVector128PrecomputedKey(Vector128<byte> key)
	{
		_key1 = PrepareKey(key);
		_keyK1 = GHashX86.GetReductionKey(_key1);

		if (IsSupported256)
		{
			_key2 = GFMultiplyPrepared(_key1, _key1, _keyK1);
			Vector256<byte> key21 = Vector256.Create(_key2, _key1);
			Vector256<byte> key22 = Vector256.Create(_key2);
			Vector256<byte> keyK22 = GHashX86.GetReductionKey(key22);
			Vector256<byte> key43 = GFMultiplyPrepared(key21, key22, keyK22);
			_keyK2 = keyK22.GetLower();
			_key3 = key43.GetUpper();
			_key4 = key43.GetLower();

			Vector256<byte> key44 = Vector256.Create(_key4);
			Vector256<byte> keyK44 = GHashX86.GetReductionKey(key44);
			_keyK4 = keyK44.GetLower();
			Vector256<byte> key65 = GFMultiplyPrepared(key21, key44, keyK44);
			_key5 = key65.GetUpper();
			_key6 = key65.GetLower();

			Vector256<byte> key87 = GFMultiplyPrepared(key43, key44, keyK44);
			_key7 = key87.GetUpper();
			_key8 = key87.GetLower();
		}
		else
		{
			_key2 = GFMultiplyPrepared(_key1, _key1, _keyK1);
			_keyK2 = GHashX86.GetReductionKey(_key2);
			_key3 = GFMultiplyPrepared(_key2, _key1, _keyK1);
			_key4 = GFMultiplyPrepared(_key2, _key2, _keyK2);
			Vector128<byte> keyK4 = GHashX86.GetReductionKey(_key4);
			_keyK4 = keyK4;
			_key5 = GFMultiplyPrepared(_key1, _key4, keyK4);
			_key6 = GFMultiplyPrepared(_key2, _key4, keyK4);
			_key7 = GFMultiplyPrepared(_key3, _key4, keyK4);
			_key8 = GFMultiplyPrepared(_key4, _key4, keyK4);
		}

		_keyK3 = GHashX86.GetReductionKey(_key3);
		_keyK5 = GHashX86.GetReductionKey(_key5);
		_keyK6 = GHashX86.GetReductionKey(_key6);
		_keyK7 = GHashX86.GetReductionKey(_key7);
		_keyK8 = GHashX86.GetReductionKey(_key8);
	}

	private void AppendBlocks(ref Vector128<byte> accumulatorDestination, scoped ReadOnlySpan<byte> source)
	{
		Vector128<byte> accumulator = accumulatorDestination;
		int offset = 0;
		int length = source.Length;
		ref byte ptr = ref source.GetReference();

		while (length >= 8 * BlockSize)
		{
			Vector128<byte> x0 = Vector128.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			Vector128<byte> x1 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 3 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x4 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 4 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x5 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 5 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x6 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 6 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x7 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 7 * BlockSize)).ReverseEndianness128();
			x0 ^= accumulator;

			GFMultiplyPreparedUnreduced(x0, _key8, _keyK8, out Vector128<byte> lo0, out Vector128<byte> hi0);
			GFMultiplyPreparedUnreduced(x1, _key7, _keyK7, out Vector128<byte> lo1, out Vector128<byte> hi1);
			GFMultiplyPreparedUnreduced(x2, _key6, _keyK6, out Vector128<byte> lo2, out Vector128<byte> hi2);
			GFMultiplyPreparedUnreduced(x3, _key5, _keyK5, out Vector128<byte> lo3, out Vector128<byte> hi3);
			Vector128<byte> lo = lo0 ^ lo1 ^ lo2 ^ lo3;
			Vector128<byte> hi = hi0 ^ hi1 ^ hi2 ^ hi3;

			GFMultiplyPreparedUnreduced(x4, _key4, _keyK4, out Vector128<byte> lo4, out Vector128<byte> hi4);
			GFMultiplyPreparedUnreduced(x5, _key3, _keyK3, out Vector128<byte> lo5, out Vector128<byte> hi5);
			GFMultiplyPreparedUnreduced(x6, _key2, _keyK2, out Vector128<byte> lo6, out Vector128<byte> hi6);
			GFMultiplyPreparedUnreduced(x7, _key1, _keyK1, out Vector128<byte> lo7, out Vector128<byte> hi7);
			lo ^= lo4 ^ lo5 ^ lo6 ^ lo7;
			hi ^= hi4 ^ hi5 ^ hi6 ^ hi7;

			accumulator = ReducePrepared(lo, hi);

			offset += 8 * BlockSize;
			length -= 8 * BlockSize;
		}

		if (length >= 4 * BlockSize)
		{
			Vector128<byte> x0 = Vector128.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			Vector128<byte> x1 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + 3 * BlockSize)).ReverseEndianness128();
			x0 ^= accumulator;

			GFMultiplyPreparedUnreduced(x0, _key4, _keyK4, out Vector128<byte> lo0, out Vector128<byte> hi0);
			GFMultiplyPreparedUnreduced(x1, _key3, _keyK3, out Vector128<byte> lo1, out Vector128<byte> hi1);
			GFMultiplyPreparedUnreduced(x2, _key2, _keyK2, out Vector128<byte> lo2, out Vector128<byte> hi2);
			GFMultiplyPreparedUnreduced(x3, _key1, _keyK1, out Vector128<byte> lo3, out Vector128<byte> hi3);
			accumulator = ReducePrepared(lo0 ^ lo1 ^ lo2 ^ lo3, hi0 ^ hi1 ^ hi2 ^ hi3);

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length >= 2 * BlockSize)
		{
			Vector128<byte> x0 = Vector128.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			Vector128<byte> x1 = Vector128.LoadUnsafe(ref ptr, (nuint)(offset + BlockSize)).ReverseEndianness128();
			x0 ^= accumulator;
			GFMultiplyPreparedUnreduced(x0, _key2, _keyK2, out Vector128<byte> lo0, out Vector128<byte> hi0);
			GFMultiplyPreparedUnreduced(x1, _key1, _keyK1, out Vector128<byte> lo1, out Vector128<byte> hi1);
			accumulator = ReducePrepared(lo0 ^ lo1, hi0 ^ hi1);

			offset += 2 * BlockSize;
			length -= 2 * BlockSize;
		}

		if (length is BlockSize)
		{
			Vector128<byte> block = Vector128.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			accumulator = GFMultiplyPrepared(block ^ accumulator, _key1, _keyK1);
		}

		accumulatorDestination = accumulator;
	}

	private void AppendFoldedRemainder(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> suffix)
	{
		int sourceBlocks = source.Length / BlockSize;
		int blockCount = sourceBlocks + (suffix.IsEmpty ? 0 : 1);
		Debug.Assert(source.Length % BlockSize is 0);
		Debug.Assert(suffix.IsEmpty || suffix.Length is BlockSize);
		Debug.Assert(blockCount is > 0 and <= 8);

		Vector128<byte> block = sourceBlocks is 0 ? Vector128.LoadUnsafe(ref suffix.GetReference()).ReverseEndianness128() : Vector128.LoadUnsafe(ref source.GetReference()).ReverseEndianness128();

		block ^= accumulator;

		GFMultiplyPreparedUnreduced(block, GetKey(blockCount), GetReductionKey(blockCount), out Vector128<byte> lo, out Vector128<byte> hi);

		ref byte input = ref source.GetReference();

		for (int i = 1; i < sourceBlocks; ++i)
		{
			block = Vector128.LoadUnsafe(ref input, (nuint)(i * BlockSize)).ReverseEndianness128();
			GFMultiplyPreparedUnreduced(block, GetKey(blockCount - i), GetReductionKey(blockCount - i), out Vector128<byte> nextLo, out Vector128<byte> nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
		}

		if (!suffix.IsEmpty && sourceBlocks is not 0)
		{
			block = Vector128.LoadUnsafe(ref suffix.GetReference()).ReverseEndianness128();
			GFMultiplyPreparedUnreduced(block, _key1, _keyK1, out Vector128<byte> nextLo, out Vector128<byte> nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
		}

		accumulator = ReducePrepared(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private Vector128<byte> GetKey(int power)
	{
		return power switch
		{
			1 => _key1,
			2 => _key2,
			3 => _key3,
			4 => _key4,
			5 => _key5,
			6 => _key6,
			7 => _key7,
			_ => _key8
		};
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private Vector128<byte> GetReductionKey(int power)
	{
		return power switch
		{
			1 => _keyK1,
			2 => _keyK2,
			3 => _keyK3,
			4 => _keyK4,
			5 => _keyK5,
			6 => _keyK6,
			7 => _keyK7,
			_ => _keyK8
		};
	}

	internal void AppendPaddedSegment(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
	{
		int completeLength = source.Length & -BlockSize;
		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			if (completeLength is not 0)
			{
				AppendBlocks(ref accumulator, source.Slice(0, completeLength));
			}

			return;
		}

		int bulkLength = completeLength & -(8 * BlockSize);

		if (bulkLength is not 0)
		{
			AppendBlocks(ref accumulator, source.Slice(0, bulkLength));
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());
		AppendFoldedRemainder(ref accumulator, source.Slice(bulkLength, completeLength - bulkLength), finalBlock.AsReadOnlySpan());
	}
}
