using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Macs.GHash;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class GHashBenchmark
{
	[Params(1024, 8192)]
	public int ByteLength { get; set; }

	private IMac _softwareFallback = null!;
	private IMac? _x86;
	private byte[] _input = [];
	private byte[] _mac = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);

		_softwareFallback = new GHashSF(key);
		_x86 = GHashX86.IsSupported ? new GHashX86(key) : default(IMac);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_mac = new byte[16];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_softwareFallback.Dispose();
		_x86?.Dispose();
	}

	private void Test(IMac mac)
	{
		mac.Update(_input);
		mac.GetMac(_mac);
	}

	[Benchmark(Baseline = true)]
	public void SoftwareFallback()
	{
		Test(_softwareFallback);
	}

	[Benchmark]
	public void X86()
	{
		Test(_x86 ?? throw new NotSupportedException());
	}
}
