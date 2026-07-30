using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

/// <summary>
/// SHA 家族没有库内自研实现，此基准用于对比 DigestUtils 默认返回的 .NET 包装与 BouncyCastle
/// </summary>
[MemoryDiagnoser]
public class ShaBenchmark
{
	[Params(DigestType.Sha1, DigestType.Sha256, DigestType.Sha384, DigestType.Sha512)]
	public DigestType Type { get; set; }

	[Params(32, 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private IHash _dotNet = null!;
	private IHash _bc = null!;
	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_dotNet = DigestUtils.Create(Type);
		_bc = Type switch
		{
			DigestType.Sha1 => new BcSHA1Digest(),
			DigestType.Sha256 => new BcSHA256Digest(),
			DigestType.Sha384 => new BcSHA384Digest(),
			DigestType.Sha512 => new BcSHA512Digest(),
			_ => throw new ArgumentOutOfRangeException(nameof(Type), Type, default)
		};
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[_dotNet.Length];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_dotNet.Dispose();
		_bc.Dispose();
	}

	private void Test(IHash hash)
	{
		hash.UpdateFinal(_input, _hash);
	}

	[Benchmark(Baseline = true)]
	public void DotNet()
	{
		Test(_dotNet);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Test(_bc);
	}
}
