using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Crc32C;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Crc32C;

[MemoryDiagnoser]
public class Crc32CBenchmark
{
	[Params(8, 16, 128, 256, 1024, 8192, 1024 * 1024)]
	public int ByteLength { get; set; }

	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[HashAlgorithm<Crc32CHashAlgorithm>.HashLengthInBytes];
	}

	[Benchmark]
	public void CryptoBase()
	{
		HashAlgorithm<Crc32CHashAlgorithm>.HashData(_input, _hash);
	}
}
