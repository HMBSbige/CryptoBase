using static CryptoBase.Ciphers.Modes.Gcm.GHashX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal readonly struct GHashFourBlockPrecomputedKey : IGHashPowers
{
	private readonly Vector128<byte> _key1;
	private readonly Vector128<byte> _key2;
	private readonly Vector128<byte> _key3;
	private readonly Vector128<byte> _key4;

	internal GHashFourBlockPrecomputedKey(Vector128<byte> key)
	{
		_key1 = key;

		if (IsSupported256)
		{
			GetFirstFourPowers(_key1, out Vector256<byte> key21, out Vector256<byte> key43);
			_key2 = key21.GetLower();
			_key3 = key43.GetUpper();
			_key4 = key43.GetLower();
		}
		else
		{
			_key2 = GFSquare(_key1);
			_key3 = GFMultiply(_key2, _key1);
			_key4 = GFSquare(_key2);
		}
	}

	private void AppendBlocks(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source)
	{
		if (IsSupported256)
		{
			AppendBlocks256(ref accumulator, source);
		}
		else
		{
			AppendBlocks128(ref accumulator, source);
		}
	}

	private void AppendBlocks256(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source)
	{
		int offset = 0;
		int length = source.Length;
		ref byte input = ref source.GetReference();
		Vector256<byte> key21 = Vector256.Create(_key2, _key1);
		Vector256<byte> key43 = Vector256.Create(_key4, _key3);

		while (length >= 4 * BlockSize)
		{
			Vector256<byte> blocks01 = Vector256.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128();
			Vector256<byte> blocks23 = Vector256.LoadUnsafe(ref input, (nuint)(offset + 2 * BlockSize)).ReverseEndianness128();
			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref blocks01);
			firstBlock ^= accumulator;

			GFMultiplyUnreduced(key43, blocks01, out Vector256<uint> p00, out Vector256<uint> p11, out Vector256<uint> pm);
			GFMultiplyUnreduced(key21, blocks23, out Vector256<uint> nextP00, out Vector256<uint> nextP11, out Vector256<uint> nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
			AssembleProduct(p00.GetLower() ^ p00.GetUpper(), p11.GetLower() ^ p11.GetUpper(), pm.GetLower() ^ pm.GetUpper(), out Vector128<uint> lo, out Vector128<uint> hi);
			accumulator = Reduce(lo, hi);

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length is 3 * BlockSize)
		{
			Vector256<byte> blocks01 = Vector256.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128();
			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref blocks01);
			firstBlock ^= accumulator;
			Vector128<byte> block2 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 2 * BlockSize)).ReverseEndianness128();

			GFMultiplyUnreduced(Vector256.Create(_key3, _key2), blocks01, out Vector256<uint> p00, out Vector256<uint> p11, out Vector256<uint> pm);
			GFMultiplyUnreduced(_key1, block2, out Vector128<uint> lastP00, out Vector128<uint> lastP11, out Vector128<uint> lastPm);
			AssembleProduct(p00.GetLower() ^ p00.GetUpper() ^ lastP00, p11.GetLower() ^ p11.GetUpper() ^ lastP11, pm.GetLower() ^ pm.GetUpper() ^ lastPm, out Vector128<uint> lo, out Vector128<uint> hi);
			accumulator = Reduce(lo, hi);
			return;
		}

		if (length is 2 * BlockSize)
		{
			Vector256<byte> blocks = Vector256.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128();
			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref blocks);
			firstBlock ^= accumulator;
			GFMultiplyUnreduced(key21, blocks, out Vector256<uint> p00, out Vector256<uint> p11, out Vector256<uint> pm);
			AssembleProduct(p00.GetLower() ^ p00.GetUpper(), p11.GetLower() ^ p11.GetUpper(), pm.GetLower() ^ pm.GetUpper(), out Vector128<uint> lo, out Vector128<uint> hi);
			accumulator = Reduce(lo, hi);
			return;
		}

		if (length is BlockSize)
		{
			Vector128<byte> block = Vector128.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128();
			accumulator = GFMultiply(_key1, block ^ accumulator);
		}
	}

	private void AppendBlocks128(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source)
	{
		int offset = 0;
		int length = source.Length;
		ref byte input = ref source.GetReference();

		while (length >= 4 * BlockSize)
		{
			Vector128<byte> x0 = Vector128.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128() ^ accumulator;
			Vector128<byte> x1 = Vector128.LoadUnsafe(ref input, (nuint)(offset + BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 3 * BlockSize)).ReverseEndianness128();

			GFMultiplyUnreduced(_key4, x0, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);
			GFMultiplyUnreduced(_key3, x1, out Vector128<uint> nextP00, out Vector128<uint> nextP11, out Vector128<uint> nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
			GFMultiplyUnreduced(_key2, x2, out nextP00, out nextP11, out nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
			GFMultiplyUnreduced(_key1, x3, out nextP00, out nextP11, out nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
			AssembleProduct(p00, p11, pm, out Vector128<uint> lo, out Vector128<uint> hi);
			accumulator = Reduce(lo, hi);

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length is 3 * BlockSize)
		{
			Vector128<byte> x0 = Vector128.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128() ^ accumulator;
			Vector128<byte> x1 = Vector128.LoadUnsafe(ref input, (nuint)(offset + BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 2 * BlockSize)).ReverseEndianness128();
			GFMultiplyUnreduced(_key3, x0, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);
			GFMultiplyUnreduced(_key2, x1, out Vector128<uint> nextP00, out Vector128<uint> nextP11, out Vector128<uint> nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
			GFMultiplyUnreduced(_key1, x2, out nextP00, out nextP11, out nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
			AssembleProduct(p00, p11, pm, out Vector128<uint> lo, out Vector128<uint> hi);
			accumulator = Reduce(lo, hi);
			return;
		}

		if (length is 2 * BlockSize)
		{
			Vector128<byte> x0 = Vector128.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128() ^ accumulator;
			Vector128<byte> x1 = Vector128.LoadUnsafe(ref input, (nuint)(offset + BlockSize)).ReverseEndianness128();
			GFMultiplyUnreduced(_key2, x0, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);
			GFMultiplyUnreduced(_key1, x1, out Vector128<uint> nextP00, out Vector128<uint> nextP11, out Vector128<uint> nextPm);
			AssembleProduct(p00 ^ nextP00, p11 ^ nextP11, pm ^ nextPm, out Vector128<uint> lo, out Vector128<uint> hi);
			accumulator = Reduce(lo, hi);
			return;
		}

		if (length is BlockSize)
		{
			Vector128<byte> block = Vector128.LoadUnsafe(ref input, (nuint)offset).ReverseEndianness128();
			accumulator = GFMultiply(_key1, block ^ accumulator);
		}
	}

	private void AppendFoldedPaddedRemainder(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, in Vector128<byte> finalBlock)
	{
		int sourceBlocks = source.Length / BlockSize;
		Debug.Assert(source.Length % BlockSize is 0);
		Debug.Assert(sourceBlocks is >= 0 and < 4);

		Vector128<byte> block = sourceBlocks is 0 ? finalBlock.ReverseEndianness128() : Vector128.LoadUnsafe(ref source.GetReference()).ReverseEndianness128();

		block ^= accumulator;

		GFMultiplyUnreduced(GetKey(sourceBlocks + 1), block, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);

		ref byte input = ref source.GetReference();

		for (int i = 1; i < sourceBlocks; ++i)
		{
			block = Vector128.LoadUnsafe(ref input, (nuint)(i * BlockSize)).ReverseEndianness128();
			GFMultiplyUnreduced(GetKey(sourceBlocks + 1 - i), block, out Vector128<uint> nextP00, out Vector128<uint> nextP11, out Vector128<uint> nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
		}

		if (sourceBlocks is not 0)
		{
			block = finalBlock.ReverseEndianness128();
			GFMultiplyUnreduced(_key1, block, out Vector128<uint> nextP00, out Vector128<uint> nextP11, out Vector128<uint> nextPm);
			p00 ^= nextP00;
			p11 ^= nextP11;
			pm ^= nextPm;
		}

		AssembleProduct(p00, p11, pm, out Vector128<uint> lo, out Vector128<uint> hi);
		accumulator = Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private Vector128<byte> GetKey(int power)
	{
		return power switch
		{
			1 => _key1,
			2 => _key2,
			3 => _key3,
			_ => _key4
		};
	}

	public void AppendPaddedSegment(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
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

		int bulkLength = completeLength & -(4 * BlockSize);

		if (bulkLength is not 0)
		{
			AppendBlocks(ref accumulator, source.Slice(0, bulkLength));
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());
		AppendFoldedPaddedRemainder(ref accumulator, source.Slice(bulkLength, completeLength - bulkLength), in finalBlock);
	}
}
