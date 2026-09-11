using BenchmarkDotNet.Attributes;
using System.Buffers;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
[RankColumn]
public class CryptoBufferBenchmark
{
	[Params(16, 255, 256, 257, 1024, 8192)]
	public int Size { get; set; }

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		using CryptoBuffer<byte> buffer = new(Size);
	}

	[Benchmark]
	public void BclNewArray()
	{
		using CryptoBuffer<byte> buffer = new(new byte[Size]);
	}

	[Benchmark]
	public void BclStackAlloc()
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[Size]);
	}

	[Benchmark]
	public void BclAllocateUninitializedArray()
	{
		using CryptoBuffer<byte> buffer = new(GC.AllocateUninitializedArray<byte>(Size));
	}

	[Benchmark]
	public void BclArrayPool()
	{
		byte[] tmp = ArrayPool<byte>.Shared.Rent(Size);

		try
		{
			using CryptoBuffer<byte> buffer = new(tmp.AsSpan(0, Size));
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(tmp);
		}
	}
}
