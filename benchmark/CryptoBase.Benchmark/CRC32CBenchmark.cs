using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.CRC32C;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

/// <summary>
/// CRC-32C 与 CRC-32 是不同多项式，单独成类避免误导性的 Ratio 对比
/// </summary>
[MemoryDiagnoser]
public class CRC32CBenchmark
{
	[Params(32, 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private IHash _crc32C = null!;
	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_crc32C = new Crc32C();
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[HashConstants.Crc32Length];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_crc32C.Dispose();
	}

	[Benchmark]
	public void Crc32C()
	{
		_crc32C.UpdateFinal(_input, _hash);
	}
}
