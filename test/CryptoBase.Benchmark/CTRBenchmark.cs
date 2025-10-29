using BenchmarkDotNet.Attributes;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class CTRBenchmark
{
	[Params(1000)]
	public int Max { get; set; }

	[Params(1024, 8192, 1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey16 = null!;
	private byte[] _randomIv16 = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
		_randomKey16 = RandomNumberGenerator.GetBytes(16);
		_randomIv16 = RandomNumberGenerator.GetBytes(16);
	}

	[Benchmark(Baseline = true)]
	public void X86()
	{
		ReadOnlySpan<byte> key = _randomKey16.AsSpan();
		ReadOnlySpan<byte> iv = _randomIv16.AsSpan();
		ReadOnlySpan<byte> data = _randombytes.Span;

		using CTR128StreamModeX86 crypto = new(AesCrypto.CreateCore(key), iv);

		Span<byte> o = stackalloc byte[data.Length];

		for (int i = 0; i < Max; ++i)
		{
			crypto.Update(data, o);
		}
	}

	[Benchmark]
	public void Default()
	{
		ReadOnlySpan<byte> key = _randomKey16.AsSpan();
		ReadOnlySpan<byte> iv = _randomIv16.AsSpan();
		ReadOnlySpan<byte> data = _randombytes.Span;

		using CTR128StreamMode crypto = new(AesCrypto.CreateCore(key), iv);

		Span<byte> o = stackalloc byte[data.Length];

		for (int i = 0; i < Max; ++i)
		{
			crypto.Update(data, o);
		}
	}
}
