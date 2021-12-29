using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class ChaCha20OriginalBenchmark
{
	[Params(1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;
	private byte[] _randomIv = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = Utils.RandBytes(ByteLength).ToArray();
		_randomKey = Utils.RandBytes(32).ToArray();
		_randomIv = Utils.RandBytes(8).ToArray();
	}

	private static void Test(IStreamCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];
		crypto.Update(origin, o);

		crypto.Dispose();
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Test(new BcChaCha20OriginalCrypto(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark]
	public void SoftwareFallback()
	{
		Test(new ChaCha20OriginalCryptoSF(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark(Baseline = true)]
	public void X86()
	{
		Test(new ChaCha20OriginalCryptoX86(_randomKey, _randomIv), _randombytes.Span);
	}
}
