using BenchmarkDotNet.Attributes;
using CryptoBase.Digests.CRC32;
using CryptoBase.Digests.CRC32C;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class CRC32Benchmark
{
	[Params(32, 114514)]
	public int ByteLength { get; set; }

	private byte[] _randombytes = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
	}

	[Benchmark(Baseline = true)]
	public void Crc32C()
	{
		using Crc32C hasher = new();
		Span<byte> hash = stackalloc byte[hasher.Length];
		hasher.UpdateFinal(_randombytes, hash);
	}

	[Benchmark]
	public void Crc32SF()
	{
		using Crc32SF hasher = new();
		Span<byte> hash = stackalloc byte[hasher.Length];
		hasher.UpdateFinal(_randombytes, hash);
	}

	[Benchmark]
	public void Crc32X86()
	{
		using Crc32X86 hasher = new();
		Span<byte> hash = stackalloc byte[hasher.Length];
		hasher.UpdateFinal(_randombytes, hash);
	}
}
