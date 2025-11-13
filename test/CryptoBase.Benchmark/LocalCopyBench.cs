using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

/// <summary>
/// field load hoisting
/// </summary>
[RankColumn]
[DisassemblyDiagnoser]
public class LocalCopyBench
{
	[Params(16, 1024, 8192)]
	public int Length { get; set; }

	private byte[] _a = null!;

	[GlobalSetup]
	public void Setup()
	{
		_a = RandomNumberGenerator.GetBytes(Length);
	}

	[Benchmark(Baseline = true)]
	public void Direct()
	{
		for (int i = 0; i < _a.Length; i++)
		{
			++_a[i];
		}
	}

	[Benchmark]
	public void LocalCopy()
	{
		Span<byte> a = _a;

		for (int i = 0; i < a.Length; i++)
		{
			++a[i];
		}
	}
}
