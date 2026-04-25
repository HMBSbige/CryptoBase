using BenchmarkDotNet.Attributes;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
[RankColumn]
public class CryptoBufferBench
{
	[Params(16, 64, 256, 512, 1024, 2048, 4096, 8192, 16384)]
	public int Size { get; set; }

	[Benchmark(Baseline = true)]
	public void Default()
	{
		using CryptoBuffer<byte> buffer = new(Size);
	}

	[Benchmark]
	public void NewArray()
	{
		using CryptoBuffer<byte> buffer = new(new byte[Size]);
	}

	[Benchmark]
	public void Stack()
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[Size]);
	}

	[SkipLocalsInit]
	[Benchmark]
	public void SkipLocalsInitStack()
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[Size]);
	}

	[Benchmark]
	public void AllocateUninitializedArray()
	{
		using CryptoBuffer<byte> buffer = new(GC.AllocateUninitializedArray<byte>(Size));
	}

	[Benchmark]
	public void UseArrayPool()
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
