using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SM3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SM3Benchmark
{
	[Params(32, 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private IHash _managed = null!;
	private IHash _bc = null!;
	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_managed = new SM3Digest();
		_bc = new BcSM3Digest();
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[HashConstants.SM3Length];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_managed.Dispose();
		_bc.Dispose();
	}

	private void Test(IHash hash)
	{
		hash.UpdateFinal(_input, _hash);
	}

	[Benchmark(Baseline = true)]
	public void Managed()
	{
		Test(_managed);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Test(_bc);
	}
}
