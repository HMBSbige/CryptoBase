using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal static class Blake3Compressor
{
	// A single compression is bound by the serial dependency chain of G, so row vectors only win where vector additions, XORs and rotations take one cycle.
	// Zen 5 and ARM64 cores take two, and their wide scalar pipelines run the four independent Gs of a step side by side instead.
	internal static readonly bool PreferScalar = AdvSimd.Arm64.IsSupported || X86Base.X64.IsSupported && CpuIdUtils.IsAmdZen5();

	// Chosen apart from Blake3Tree.Kernel, which weighs many inputs side by side rather than one compression. A field, which the JIT takes as a constant;
	// as a property, the check cost every compression a call.
	private static readonly bool UseVector128 = Blake3Vector128.IsSupported && !PreferScalar;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void CompressBlocks(ref uint cv, ref byte blocks, nuint blockCount, ulong counter, uint flags, uint startFlags, uint endFlags)
	{
		if (UseVector128)
		{
			Blake3Vector128.CompressBlocks(ref cv, ref blocks, blockCount, counter, flags, startFlags, endFlags);
			return;
		}

		Blake3Scalar.CompressBlocks(ref cv, ref blocks, blockCount, counter, flags, startFlags, endFlags);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Compress(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		if (UseVector128)
		{
			Blake3Vector128.Compress(in cv, ref block, blockLength, counter, flags, ref output);
			return;
		}

		Blake3Scalar.Compress(in cv, ref block, blockLength, counter, flags, ref output);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void CompressXof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		if (UseVector128)
		{
			Blake3Vector128.CompressXof(in cv, ref block, blockLength, counter, flags, ref output);
			return;
		}

		Blake3Scalar.CompressXof(in cv, ref block, blockLength, counter, flags, ref output);
	}

	[SkipLocalsInit]
	internal static void HashChunk(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		Debug.Assert(length is > 0 and <= ChunkLength);

		InlineArray8<uint> cv = Blake3Words.Copy(in key);

		if (length is ChunkLength)
		{
			CompressBlocks(ref cv[0], ref input, ChunkBlocks, counter, flags, Blake3Flags.ChunkStart, Blake3Flags.ChunkEnd);
			Blake3Words.Store(ref output, in cv);
			return;
		}

		nuint lastBlockOffset = length - 1 & ~(nuint)(BlockLength - 1);
		uint startFlag = Blake3Flags.ChunkStart;

		if (lastBlockOffset is not 0)
		{
			CompressBlocks(ref cv[0], ref input, lastBlockOffset / BlockLength, counter, flags, startFlag, 0);
			startFlag = 0;
		}

		CompressLastBlock(in cv[0], ref Unsafe.Add(ref input, lastBlockOffset), (uint)(length - lastBlockOffset), counter, flags | startFlag, ref output);
	}

	[SkipLocalsInit]
	internal static void FinishChunk(ref byte chunk, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		Debug.Assert(length is > 0 and < ChunkLength);

		nuint lastBlockOffset = length - 1 & ~(nuint)(BlockLength - 1);

		if (lastBlockOffset is 0)
		{
			CompressLastBlock(in key, ref chunk, (uint)length, counter, flags | Blake3Flags.ChunkStart, ref output);
			return;
		}

		InlineArray8<uint> cv = Blake3Words.Load(in output);
		CompressLastBlock(in cv[0], ref Unsafe.Add(ref chunk, lastBlockOffset), (uint)(length - lastBlockOffset), counter, flags, ref output);
	}

	[SkipLocalsInit]
	private static void CompressLastBlock(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		Unsafe.SkipInit(out InlineArray64<byte> buffer);
		Span<byte> padded = buffer;
		MemoryMarshal.CreateReadOnlySpan(ref block, (int)blockLength).CopyTo(padded);
		padded.Slice((int)blockLength).Clear();
		Compress(in cv, ref padded[0], blockLength, counter, flags | Blake3Flags.ChunkEnd, ref output);
	}
}
