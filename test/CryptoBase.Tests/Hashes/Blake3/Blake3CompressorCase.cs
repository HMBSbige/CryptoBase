using CryptoBase.Hashes.Blake3;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Hashes.Blake3;

public abstract class Blake3CompressorCase
{
	public static IEnumerable<Blake3CompressorCase> All()
	{
		yield return new Compressor<Blake3Scalar>();
		yield return new Compressor<Blake3Vector128>();
	}

	public abstract Type CompressorType { get; }

	public abstract bool IsSupported { get; }

	public abstract void CompressBlocks(uint[] chainingValue, ReadOnlySpan<byte> blocks, int blockCount, ulong counter, uint flags, uint startFlags, uint endFlags);

	public abstract void Compress(uint[] chainingValue, ReadOnlySpan<byte> block, uint blockLength, ulong counter, uint flags, Span<byte> output);

	public abstract void CompressXof(uint[] chainingValue, ReadOnlySpan<byte> block, uint blockLength, ulong counter, uint flags, Span<byte> output);

	public override string ToString()
	{
		return CompressorType.Name;
	}

	private sealed class Compressor<TCompressor> : Blake3CompressorCase where TCompressor : IBlake3Compressor
	{
		public override Type CompressorType => typeof(TCompressor);

		public override bool IsSupported => TCompressor.IsSupported;

		public override void CompressBlocks(uint[] chainingValue, ReadOnlySpan<byte> blocks, int blockCount, ulong counter, uint flags, uint startFlags, uint endFlags)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(blocks.Length, blockCount * Blake3Reference.BlockLength);

			TCompressor.CompressBlocks(ref chainingValue[0], ref MemoryMarshal.GetReference(blocks), (uint)blockCount, counter, flags, startFlags, endFlags);
		}

		public override void Compress(uint[] chainingValue, ReadOnlySpan<byte> block, uint blockLength, ulong counter, uint flags, Span<byte> output)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(block.Length, Blake3Reference.BlockLength);
			ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, Blake3Reference.OutLength);

			TCompressor.Compress(in chainingValue[0], ref MemoryMarshal.GetReference(block), blockLength, counter, flags, ref MemoryMarshal.GetReference(output));
		}

		public override void CompressXof(uint[] chainingValue, ReadOnlySpan<byte> block, uint blockLength, ulong counter, uint flags, Span<byte> output)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(block.Length, Blake3Reference.BlockLength);
			ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, Blake3Reference.BlockLength);

			TCompressor.CompressXof(in chainingValue[0], ref MemoryMarshal.GetReference(block), blockLength, counter, flags, ref MemoryMarshal.GetReference(output));
		}
	}
}
