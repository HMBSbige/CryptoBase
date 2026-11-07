using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;

namespace CryptoBase.Kdf;

// The key derivation function of GB/T 32918.4-2016, Sec. 5.4.3, with SM3, which SM2 and SM9 share: the key is SM3(Z ‖ ct) for the 32-bit big-endian counters ct = 1, 2, … in order, cut to its length. The state absorbs Z once, through Append, and each block finishes a copy of it: WriteBlock one, and Write several at once in vector lanes, which share the chaining value and the bytes of Z after its last whole block. Z may be secret: the methods erase the copies they make, and Clear erases the state. Keep a state in one writable location and do not copy it.
internal struct SM3KdfState
{
	internal const int BlockLength = 32;

	private SM3Core _hash;

	// The fewest blocks that take lanes, as a group computes every lane however few blocks fill it; fewer take SM3 one block at a time. Four lanes whose rotations take three instructions need one block more.
	private static int MinLaneBlocks => SM3Vector256.IsSupported || Avx512F.VL.IsSupported || AdvSimd.Arm64.IsSupported ? 3 : 4;

	// As MinLaneBlocks for the blocks past a pass of lanes, whose group shares the call of the pass: one block fewer where rotations take one instruction.
	private static int MinRestBlocks => Avx512F.VL.IsSupported ? MinLaneBlocks - 1 : MinLaneBlocks;

	// The key that Xor and IsZero take at a time, four passes of the widest lanes.
	private const int ChunkLength = 4096;

	// The counters run to 2^32 − 1, so a key holds at most that many blocks.
	private static long MaxLength => (long)uint.MaxValue * BlockLength;

	internal void Initialize()
	{
		_hash = HashCore.Create<SM3Core>();
	}

	internal void Append(ReadOnlySpan<byte> z)
	{
		HashCore.Append(ref _hash, z);
	}

	// Writes block counter, from 1, to the first BlockLength bytes of destination.
	[SkipLocalsInit]
	internal readonly void WriteBlock(uint counter, Span<byte> destination)
	{
		Debug.Assert(counter is not 0 && destination.Length >= BlockLength);

		SM3Core block = _hash;
		Span<byte> encodedCounter = stackalloc byte[sizeof(uint)];
		BinaryPrimitives.WriteUInt32BigEndian(encodedCounter, counter);
		HashCore.Append(ref block, encodedCounter);
		HashCore.Finalize(ref block, destination);
		block.ZeroMemory();
	}

	// Writes the key from block counter on to destination, which may be empty: blocks counter, counter + 1, …, the last cut to fit, which must not run past block 2^32 − 1. Several blocks at once take vector lanes.
	internal readonly void Write(uint counter, Span<byte> destination)
	{
		Debug.Assert(counter is not 0 && counter + ((ulong)destination.Length + BlockLength - 1) / BlockLength - 1 <= uint.MaxValue);

		if (destination.Length > (MinLaneBlocks - 1) * BlockLength && SM3Vector128.IsSupported)
		{
			WriteLanes(counter, destination);
			return;
		}

		WriteBlocks(counter, destination);
	}

	// destination = source ⊕ the key from block counter on, source.Length bytes of each, taking the key a chunk at a time on the stack. Returns a value that is 0 just if every byte of the key is, without branching on them. destination is source or does not overlap it.
	[SkipLocalsInit]
	internal readonly ulong Xor(uint counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(destination.Length >= source.Length);

		int length = source.Length;
		using CryptoBuffer<byte> chunk = new(stackalloc byte[Math.Min(length, ChunkLength)]);
		ulong accumulated = 0;

		// offset steps by the chunk it took, so it stays at most length, even near int.MaxValue.
		for (int offset = 0; offset < length; counter += ChunkLength / BlockLength)
		{
			Span<byte> key = chunk.Span.Slice(0, Math.Min(ChunkLength, length - offset));
			Write(counter, key);
			accumulated |= Accumulate(key);
			FastUtils.Xor(key, source.Slice(offset), destination.Slice(offset), key.Length);
			offset += key.Length;
		}

		return accumulated;
	}

	// Whether the length bytes of the key from block counter on are all zero, a chunk at a time on the stack; it returns at the first chunk that is not.
	[SkipLocalsInit]
	internal readonly bool IsZero(uint counter, int length)
	{
		using CryptoBuffer<byte> chunk = new(stackalloc byte[Math.Min(length, ChunkLength)]);

		for (int offset = 0; offset < length; counter += ChunkLength / BlockLength)
		{
			Span<byte> key = chunk.Span.Slice(0, Math.Min(ChunkLength, length - offset));
			Write(counter, key);

			if (Accumulate(key) is not 0)
			{
				return false;
			}

			offset += key.Length;
		}

		return true;
	}

	// Writes the key of destination.Length bytes, which may be empty, from block 1 on.
	internal readonly void Derive(Span<byte> destination)
	{
		Debug.Assert(destination.Length <= MaxLength);

		Write(1, destination);
	}

	internal void Clear()
	{
		_hash.ZeroMemory();
	}

	// The OR of the bytes in words, which is 0 just if every byte is, without an early exit, so that the time depends on the length alone. Four vectors take turns, so that the ORs do not wait on one another.
	internal static ulong Accumulate(ReadOnlySpan<byte> bytes)
	{
		ref byte start = ref MemoryMarshal.GetReference(bytes);
		nuint length = (nuint)bytes.Length;
		nuint i = 0;
		ulong accumulated = 0;

		if (Vector.IsHardwareAccelerated)
		{
			nuint count = (nuint)Vector<byte>.Count;
			Vector<byte> vector0 = Vector<byte>.Zero;
			Vector<byte> vector1 = Vector<byte>.Zero;
			Vector<byte> vector2 = Vector<byte>.Zero;
			Vector<byte> vector3 = Vector<byte>.Zero;

			for (; length - i >= 4 * count; i += 4 * count)
			{
				vector0 |= Vector.LoadUnsafe(ref start, i);
				vector1 |= Vector.LoadUnsafe(ref start, i + count);
				vector2 |= Vector.LoadUnsafe(ref start, i + 2 * count);
				vector3 |= Vector.LoadUnsafe(ref start, i + 3 * count);
			}

			for (; length - i >= count; i += count)
			{
				vector0 |= Vector.LoadUnsafe(ref start, i);
			}

			Vector<ulong> words = Vector.AsVectorUInt64(vector0 | vector1 | vector2 | vector3);

			for (int j = 0; j < Vector<ulong>.Count; ++j)
			{
				accumulated |= words[j];
			}
		}

		for (; length - i >= sizeof(ulong); i += sizeof(ulong))
		{
			accumulated |= Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref start, i));
		}

		for (; i < length; ++i)
		{
			accumulated |= Unsafe.Add(ref start, i);
		}

		return accumulated;
	}

	private readonly void WriteBlocks(uint counter, Span<byte> destination)
	{
		int whole = destination.Length & ~(BlockLength - 1);

		for (int offset = 0; offset < whole; offset += BlockLength)
		{
			WriteBlock(counter++, destination.Slice(offset));
		}

		if (whole != destination.Length)
		{
			using CryptoBuffer<byte> last = new(stackalloc byte[BlockLength]);
			WriteBlock(counter, last.Span);
			last.Span.Slice(0, destination.Length - whole).CopyTo(destination.Slice(whole));
		}
	}

	// Sixteen lanes take all but up to eight blocks, which eight lanes take; what the lanes leave goes one block at a time.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private readonly void WriteLanes(uint counter, Span<byte> destination)
	{
		_hash.GetCounterBlocks(out SM3CounterBlocks blocks);

		if (SM3Vector512.IsSupported)
		{
			int wide = LaneLength(destination.Length, SM3Lanes<SM3Vector512, Vector512<uint>>.PassLength, SM3Vector256.Lanes + 1);

			if (wide is not 0)
			{
				SM3Lanes<SM3Vector512, Vector512<uint>>.Write(in blocks, counter, destination.Slice(0, wide));
				counter += (uint)wide / BlockLength;
				destination = destination.Slice(wide);
			}
		}

		int length = LaneLength(destination.Length, SM3Vector256.IsSupported ? SM3Lanes<SM3Vector256, Vector256<uint>>.PassLength : SM3Lanes<SM3Vector128, Vector128<uint>>.PassLength, MinRestBlocks);

		if (length is not 0)
		{
			if (SM3Vector256.IsSupported)
			{
				SM3Lanes<SM3Vector256, Vector256<uint>>.Write(in blocks, counter, destination.Slice(0, length));
			}
			else
			{
				SM3Lanes<SM3Vector128, Vector128<uint>>.Write(in blocks, counter, destination.Slice(0, length));
			}

			counter += (uint)length / BlockLength;
			destination = destination.Slice(length);
		}

		blocks.ZeroMemory();
		WriteBlocks(counter, destination);
	}

	// What lanes that take passLength bytes a pass take of a key of length bytes: none of fewer than MinLaneBlocks blocks, and all but what is left past their last pass if fewer than minRestBlocks.
	private static int LaneLength(int length, int passLength, int minRestBlocks)
	{
		if (length <= (MinLaneBlocks - 1) * BlockLength)
		{
			return 0;
		}

		int rest = (int)((uint)length % (uint)passLength);
		return rest <= (minRestBlocks - 1) * BlockLength ? length - rest : length;
	}
}
