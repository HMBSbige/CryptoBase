using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Crc32;
using System.Security.Cryptography;
using DotNetCrc32 = System.IO.Hashing.Crc32;

namespace CryptoBase.Benchmark.Hashes.Crc32;

[MemoryDiagnoser]
public class Crc32Benchmark
{
	[Params(8, 16, 128, 256, 1024, 8192, 1024 * 1024)]
	public int ByteLength { get; set; }

	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[HashAlgorithm<Crc32HashAlgorithm>.HashLength];
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		HashAlgorithm<Crc32HashAlgorithm>.HashData(_input, _hash);
	}

	[Benchmark]
	public void DotNet()
	{
		DotNetCrc32.Hash(_input, _hash);
	}
}
