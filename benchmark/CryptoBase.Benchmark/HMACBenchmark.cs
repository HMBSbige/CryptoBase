using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Digests;
using CryptoBase.Macs.Hmac;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class HMACBenchmark
{
	[Params(32, 1024, 8192)]
	public int ByteLength { get; set; }

	/// <summary>
	/// HmacUtils.Create(DigestType, key) 对 SHA-2 家族返回的 .NET IncrementalHash 路径
	/// </summary>
	private IMac _default = null!;

	/// <summary>
	/// 库自研的 HmacSF 实现（生产中用于无 .NET 内置 HMAC 的摘要，如 SM3）
	/// </summary>
	private IMac _managed = null!;

	private byte[] _input = [];
	private byte[] _mac = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(64);

		_default = HmacUtils.Create(DigestType.Sha256, key);
		_managed = HmacUtils.Create(key, DigestUtils.Create(DigestType.Sha256));
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_mac = new byte[_default.Length];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_default.Dispose();
		_managed.Dispose();
	}

	private void Test(IMac mac)
	{
		mac.Update(_input);
		mac.GetMac(_mac);
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		Test(_default);
	}

	[Benchmark]
	public void Managed()
	{
		Test(_managed);
	}
}
