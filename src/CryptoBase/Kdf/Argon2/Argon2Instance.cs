using static CryptoBase.Kdf.Argon2.Argon2Core;

namespace CryptoBase.Kdf.Argon2;

internal sealed unsafe class Argon2Instance<TKernel> : Argon2LaneScheduler where TKernel : IArgon2Kernel
{
	private const int WipePass = -1;

	// Data-independent references are known up to an address block in advance, so their blocks are prefetched this many blocks ahead.
	private const int PrefetchDistance = 8;
	private const int CacheLineSize = 64;

	private readonly Argon2Block* _memory;
	private readonly Argon2Type _type;
	private readonly int _segmentLength;
	private readonly int _laneLength;
	private readonly int _passes;
	private readonly bool _prefetch;

	private byte* _prehash;

	internal Argon2Instance(Argon2Block* memory, Argon2Type type, int lanes, int segmentLength, int passes, int maxDegreeOfParallelism, bool prefetch) : base(lanes, maxDegreeOfParallelism)
	{
		Debug.Assert(segmentLength >= 2);

		_memory = memory;
		_type = type;
		_segmentLength = segmentLength;
		_laneLength = segmentLength * SyncPoints;
		_passes = passes;
		_prefetch = prefetch;
	}

	internal void Derive(ReadOnlySpan<byte> prehash, Span<byte> destination)
	{
		Debug.Assert(prehash.Length is PrehashLength);

		fixed (byte* prehashPointer = prehash)
		{
			_prehash = prehashPointer;
			Argon2Block finalBlock = default;

			try
			{
				StartHelpers();

				for (int pass = 0; pass < _passes; ++pass)
				{
					for (int slice = 0; slice < SyncPoints; ++slice)
					{
						RunPhase(pass, slice);
					}
				}

				Argon2Block* lastBlock = _memory + (_laneLength - 1);
				finalBlock = *lastBlock;
				Span<ulong> finalWords = finalBlock;
				Span<byte> final = MemoryMarshal.AsBytes(finalWords);

				for (int lane = 1; lane < Lanes; ++lane)
				{
					lastBlock += _laneLength;
					FastUtils.Xor(final, new ReadOnlySpan<byte>(lastBlock, Argon2Block.SizeInBytes), final, Argon2Block.SizeInBytes);
				}

				RunPhase(WipePass, 0);

				HashVariable(final, destination);
			}
			finally
			{
				finalBlock.ZeroMemory();

				StopHelpers();
				_prehash = null;
			}
		}
	}

	protected override void ProcessLane(int pass, int slice, int lane)
	{
		if (pass is WipePass)
		{
			NativeMemory.Clear(_memory + (nint)lane * _laneLength, (nuint)_laneLength * Argon2Block.SizeInBytes);
			return;
		}

		if (pass is 0 && slice is 0)
		{
			// The first segment of a lane only references the lane itself, so the phase that fills it also initializes the lane.
			InitializeLane(lane);
		}

		// The type selects the addressing of whole segments, so the loops filling them do not depend on it.
		switch (_type, pass, slice)
		{
			case (Argon2Type.Argon2i, 0, _):
			case (Argon2Type.Argon2id, 0, < SyncPoints / 2):
			{
				FillDataIndependentSegment<Argon2FirstPass>(pass, slice, lane);
				break;
			}
			case (Argon2Type.Argon2i, _, _):
			{
				FillDataIndependentSegment<Argon2LaterPass>(pass, slice, lane);
				break;
			}
			case (Argon2Type.Argon2d, 0, 0):
			{
				FillFirstDataDependentSegment(lane);
				break;
			}
			default:
			{
				FillDataDependentSegment(pass, slice, lane);
				break;
			}
		}
	}

	[SkipLocalsInit]
	private void InitializeLane(int lane)
	{
		using CryptoBuffer<byte> seedBuffer = new(stackalloc byte[PrehashLength + 2 * sizeof(uint)]);
		Span<byte> seed = seedBuffer.Span;
		Argon2Block* laneBlocks = _memory + (nint)lane * _laneLength;

		new ReadOnlySpan<byte>(_prehash, PrehashLength).CopyTo(seed);
		BinaryPrimitives.WriteUInt32LittleEndian(seed.Slice(PrehashLength + sizeof(uint)), (uint)lane);

		for (int i = 0; i < 2; ++i)
		{
			BinaryPrimitives.WriteUInt32LittleEndian(seed.Slice(PrehashLength), (uint)i);
			Span<ulong> block = laneBlocks[i];
			HashVariable(seed, MemoryMarshal.AsBytes(block));
		}
	}

	// TPass makes the pass a constant in the first pass, the only one Argon2id fills here, so that supporting the later passes of Argon2i costs Argon2id no registers.
	[SkipLocalsInit]
	private void FillDataIndependentSegment<TPass>(int pass, int slice, int lane) where TPass : struct, IArgon2Pass
	{
		Debug.Assert(TPass.IsFirst == pass is 0);

		if (TPass.IsFirst)
		{
			pass = 0;
		}

		int segmentLength = _segmentLength;
		int laneLength = _laneLength;
		Argon2Block* laneBlocks = _memory + (nint)lane * laneLength;
		Argon2ReferenceSet references = new(_memory, Lanes, segmentLength, pass, slice, lane);
		bool prefetch = _prefetch;
		bool xorDestination = !TPass.IsFirst;
		int startIndex = TPass.IsFirst && slice is 0 ? 2 : 0;

		Unsafe.SkipInit(out Argon2Block scratch);
		Argon2Block zero = default;
		Argon2Block input = default;
		Unsafe.SkipInit(out Argon2Block addressesA);
		Unsafe.SkipInit(out Argon2Block addressesB);

		// Each address block is computed PrefetchDistance blocks before it is needed, so that the first blocks it addresses can be prefetched too.
		ref Argon2Block addresses = ref addressesA;
		ref Argon2Block upcoming = ref addressesB;

		try
		{
			input[0] = (ulong)pass;
			input[1] = (ulong)lane;
			input[2] = (ulong)slice;
			input[3] = (ulong)laneLength * (ulong)Lanes;
			input[4] = (ulong)_passes;
			input[5] = (ulong)_type;

			NextAddresses(ref zero, ref input, ref addresses, ref scratch);

			int current = slice * segmentLength + startIndex;
			int previous = TPass.IsFirst || current is not 0 ? current - 1 : laneLength - 1;

			for (int index = startIndex; index < segmentLength; ++index)
			{
				int addressIndex = (int)((uint)index % Argon2Block.QWordCount);

				if (addressIndex is 0 && index != startIndex)
				{
					ref Argon2Block swapped = ref addresses;
					addresses = ref upcoming;
					upcoming = ref swapped;
				}

				if (index + PrefetchDistance < segmentLength)
				{
					int ahead = addressIndex + PrefetchDistance;

					if (ahead is Argon2Block.QWordCount)
					{
						NextAddresses(ref zero, ref input, ref upcoming, ref scratch);
					}

					if (prefetch)
					{
						ulong pseudoRandom = ahead < Argon2Block.QWordCount ? addresses[ahead] : upcoming[ahead - Argon2Block.QWordCount];
						Prefetch(references.Locate(pseudoRandom, index + PrefetchDistance));
					}
				}

				Argon2Block* reference = references.Locate(addresses[addressIndex], index);
				TKernel.Compress(ref laneBlocks[previous], ref *reference, ref laneBlocks[current], ref scratch, xorDestination);
				previous = current++;
			}
		}
		finally
		{
			// Only scratch needs wiping: the address blocks depend only on public parameters.
			scratch.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void FillDataDependentSegment(int pass, int slice, int lane)
	{
		int segmentLength = _segmentLength;
		int laneLength = _laneLength;
		Argon2Block* laneBlocks = _memory + (nint)lane * laneLength;
		Argon2ReferenceSet references = new(_memory, Lanes, segmentLength, pass, slice, lane);
		bool xorDestination = pass is not 0;
		int current = slice * segmentLength;
		int previous = current is 0 ? laneLength - 1 : current - 1;

		Debug.Assert(pass is not 0 || slice is not 0);

		if (TKernel.TryCompressChain(ref laneBlocks[previous], ref laneBlocks[current], 0, segmentLength, references, xorDestination))
		{
			return;
		}

		Unsafe.SkipInit(out Argon2Block scratch);

		try
		{
			for (int index = 0; index < segmentLength; ++index)
			{
				Argon2Block* reference = references.Locate(laneBlocks[previous][0], index);
				TKernel.Compress(ref laneBlocks[previous], ref *reference, ref laneBlocks[current], ref scratch, xorDestination);
				previous = current++;
			}
		}
		finally
		{
			scratch.ZeroMemory();
		}
	}

	// The first Argon2d segment of a lane references only that lane and starts after the two blocks InitializeLane computes. Starting FillDataDependentSegment past index 0 would make the JIT keep fewer of its values in registers.
	[SkipLocalsInit]
	private void FillFirstDataDependentSegment(int lane)
	{
		int segmentLength = _segmentLength;
		Argon2Block* laneBlocks = _memory + (nint)lane * _laneLength;
		Argon2ReferenceSet references = new(_memory, Lanes, segmentLength, 0, 0, lane);

		if (TKernel.TryCompressChain(ref laneBlocks[1], ref laneBlocks[0], 2, segmentLength, references, false))
		{
			return;
		}

		Unsafe.SkipInit(out Argon2Block scratch);

		try
		{
			for (int index = 2; index < segmentLength; ++index)
			{
				Argon2Block* reference = references.LocateInOwnLane(laneBlocks[index - 1][0], index);
				TKernel.Compress(ref laneBlocks[index - 1], ref *reference, ref laneBlocks[index], ref scratch, false);
			}
		}
		finally
		{
			scratch.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Prefetch(Argon2Block* block)
	{
		if (!Sse.IsSupported)
		{
			return;
		}

		for (byte* line = (byte*)block, end = (byte*)(block + 1); line < end; line += CacheLineSize)
		{
			Sse.Prefetch0(line);
		}
	}

	[SkipLocalsInit]
	private static void NextAddresses(ref Argon2Block zero, ref Argon2Block input, ref Argon2Block addresses, ref Argon2Block scratch)
	{
		++input[6];
		Unsafe.SkipInit(out Argon2Block intermediate);
		TKernel.Compress(ref zero, ref input, ref intermediate, ref scratch, false);
		TKernel.Compress(ref zero, ref intermediate, ref addresses, ref scratch, false);
	}
}
