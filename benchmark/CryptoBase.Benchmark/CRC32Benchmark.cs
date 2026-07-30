using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.CRC32;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class CRC32Benchmark
{
	[Params(32, 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private IHash _softwareFallback = null!;
	private IHash? _x86;
	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_softwareFallback = new Crc32SF();
		_x86 = Crc32X86.IsSupport ? new Crc32X86() : default(IHash);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[HashConstants.Crc32Length];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_softwareFallback.Dispose();
		_x86?.Dispose();
	}

	private void Test(IHash hash)
	{
		hash.UpdateFinal(_input, _hash);
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
