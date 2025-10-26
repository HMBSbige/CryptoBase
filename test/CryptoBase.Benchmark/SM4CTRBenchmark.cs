using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
[RankColumn]
public class SM4CTRBenchmark
{
	[Params(1024, 8192, 1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;
	private byte[] _randomIv = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
		_randomKey = RandomNumberGenerator.GetBytes(16);
		_randomIv = RandomNumberGenerator.GetBytes(16);
	}

	private static void Test(IStreamCrypto crypto, ReadOnlySpan<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (int i = 0; i < 1000; ++i)
		{
			crypto.Update(origin, o);
		}
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		ReadOnlySpan<byte> key = _randomKey;
		ReadOnlySpan<byte> iv = _randomIv;
		ReadOnlySpan<byte> data = _randombytes.Span;
		using CTR128StreamMode crypto = new(new SM4Crypto(key), iv);
		Test(crypto, data);
	}

	[Benchmark]
	public void X86()
	{
		ReadOnlySpan<byte> key = _randomKey;
		ReadOnlySpan<byte> iv = _randomIv;
		ReadOnlySpan<byte> data = _randombytes.Span;
		using CTR128StreamModeX86 crypto = new(new SM4Crypto(key), iv);
		Test(crypto, data);
	}

	[Benchmark]
	public void Block4X86()
	{
		ReadOnlySpan<byte> key = _randomKey;
		ReadOnlySpan<byte> iv = _randomIv;
		ReadOnlySpan<byte> data = _randombytes.Span;
		using CTR128StreamModeBlock4X86 crypto = new(new SM4CryptoX86(key), iv);
		Test(crypto, data);
	}

	[Benchmark]
	public void Block8X86()
	{
		ReadOnlySpan<byte> key = _randomKey;
		ReadOnlySpan<byte> iv = _randomIv;
		ReadOnlySpan<byte> data = _randombytes.Span;
		using CTR128StreamModeBlock8X86 crypto = new(new SM4CryptoBlock8X86(key), iv);
		Test(crypto, data);
	}

	[Benchmark]
	public void Block8AvxX86()
	{
		ReadOnlySpan<byte> key = _randomKey;
		ReadOnlySpan<byte> iv = _randomIv;
		ReadOnlySpan<byte> data = _randombytes.Span;
		using CTR128StreamModeBlock8AvxX86 crypto = new(new SM4CryptoBlock8X86(key), iv);
		Test(crypto, data);
	}

	[Benchmark]
	public void Block16X86()
	{
		ReadOnlySpan<byte> key = _randomKey;
		ReadOnlySpan<byte> iv = _randomIv;
		ReadOnlySpan<byte> data = _randombytes.Span;
		using CTR128StreamModeBlock16X86 crypto = new(new SM4CryptoBlock16X86(key), iv);
		Test(crypto, data);
	}
}
