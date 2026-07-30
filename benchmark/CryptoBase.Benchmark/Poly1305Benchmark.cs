using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Macs.Poly1305;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

/// <summary>
/// Poly1305 是一次性密钥 MAC，真实用法（如 AEAD）每条消息都会重新构造，
/// 因此构造成本刻意保留在测量区域内，结果表示单条消息的完整 MAC 开销
/// </summary>
[MemoryDiagnoser]
public class Poly1305Benchmark
{
	[Params(16, 1024, 8192)]
	public int ByteLength { get; set; }

	private byte[] _key = [];
	private byte[] _input = [];
	private byte[] _mac = [];

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(32);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_mac = new byte[16];
	}

	private void Test<T>(T mac) where T : IMac, allows ref struct
	{
		mac.Update(_input);
		mac.GetMac(_mac);

		mac.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		Test(new Poly1305(_key));
	}

	[Benchmark]
	public void X86()
	{
		if (!Poly1305X86.IsSupported)
		{
			throw new NotSupportedException();
		}

		Test(new Poly1305X86(_key));
	}

	[Benchmark]
	public void SoftwareFallback()
	{
		Test(new Poly1305SF(_key));
	}
}
