using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes.Blake3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Blake3;

[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class Blake3CompressorBenchmark
{
	private readonly uint[] _chainingValue = [.. Blake3Constants.IV];
	private readonly byte[] _chunk = RandomNumberGenerator.GetBytes(Blake3Constants.ChunkLength);
	private readonly byte[] _output = new byte[Blake3Constants.BlockLength];

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Chunk")]
	public void ScalarChunk()
	{
		Blake3Scalar.CompressBlocks(ref _chainingValue[0], ref _chunk[0], Blake3Constants.ChunkBlocks, 0, 0, Blake3Flags.ChunkStart, Blake3Flags.ChunkEnd);
	}

	[Benchmark]
	[BenchmarkCategory("Chunk")]
	public void Vector128Chunk()
	{
		ThrowIfVector128Unsupported();
		Blake3Vector128.CompressBlocks(ref _chainingValue[0], ref _chunk[0], Blake3Constants.ChunkBlocks, 0, 0, Blake3Flags.ChunkStart, Blake3Flags.ChunkEnd);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Block")]
	public void ScalarBlock()
	{
		Blake3Scalar.Compress(in _chainingValue[0], ref _chunk[0], Blake3Constants.BlockLength, 0, Blake3Flags.Parent, ref _output[0]);
	}

	[Benchmark]
	[BenchmarkCategory("Block")]
	public void Vector128Block()
	{
		ThrowIfVector128Unsupported();
		Blake3Vector128.Compress(in _chainingValue[0], ref _chunk[0], Blake3Constants.BlockLength, 0, Blake3Flags.Parent, ref _output[0]);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Xof")]
	public void ScalarXof()
	{
		Blake3Scalar.CompressXof(in _chainingValue[0], ref _chunk[0], Blake3Constants.BlockLength, 0, Blake3Flags.Parent | Blake3Flags.Root, ref _output[0]);
	}

	[Benchmark]
	[BenchmarkCategory("Xof")]
	public void Vector128Xof()
	{
		ThrowIfVector128Unsupported();
		Blake3Vector128.CompressXof(in _chainingValue[0], ref _chunk[0], Blake3Constants.BlockLength, 0, Blake3Flags.Parent | Blake3Flags.Root, ref _output[0]);
	}

	private static void ThrowIfVector128Unsupported()
	{
		if (!Blake3Vector128.IsSupported)
		{
			throw new PlatformNotSupportedException($"{nameof(Blake3Vector128)} is not supported in this process.");
		}
	}
}
