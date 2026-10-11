using BenchmarkDotNet.Attributes;
using CryptoBase.Kdf.Argon2;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kdf;

public unsafe class Argon2KernelBenchmark
{
	private const int BlockCount = 256;

	private Argon2Block* _blocks;
	private Argon2Block _scratch;

	[Params(false, true)]
	public bool XorDestination { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_blocks = (Argon2Block*)NativeMemory.AlignedAlloc(BlockCount * (nuint)Argon2Block.SizeInBytes, Argon2MemoryCache.Alignment);
		RandomNumberGenerator.Fill(new Span<byte>(_blocks, BlockCount * Argon2Block.SizeInBytes));
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		NativeMemory.AlignedFree(_blocks);
	}

	[Benchmark(Baseline = true, OperationsPerInvoke = BlockCount - 1)]
	public void Scalar()
	{
		Fill<Argon2Scalar>();
	}

	[Benchmark(OperationsPerInvoke = BlockCount - 1)]
	public void Vector128()
	{
		Fill<Argon2Vector128>();
	}

	[Benchmark(OperationsPerInvoke = BlockCount - 1)]
	public void AdvSimd()
	{
		Fill<Argon2AdvSimd>();
	}

	[Benchmark(OperationsPerInvoke = BlockCount - 1)]
	public void Vector256()
	{
		Fill<Argon2Vector256>();
	}

	[Benchmark(OperationsPerInvoke = BlockCount - 1)]
	public void Vector512()
	{
		Fill<Argon2Vector512>();
	}

	private void Fill<TKernel>() where TKernel : IArgon2Kernel
	{
		if (!TKernel.IsSupported)
		{
			throw new PlatformNotSupportedException($"{typeof(TKernel).Name} is not supported in this process.");
		}

		Argon2Block* blocks = _blocks;
		bool xorDestination = XorDestination;

		for (int i = 1; i < BlockCount; ++i)
		{
			TKernel.Compress(ref blocks[i - 1], ref blocks[(i + BlockCount / 2) % BlockCount], ref blocks[i], ref _scratch, xorDestination);
		}
	}
}
