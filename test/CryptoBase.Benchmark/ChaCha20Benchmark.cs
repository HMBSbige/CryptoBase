using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class ChaCha20Benchmark
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
		_randomKey = RandomNumberGenerator.GetBytes(32);
		_randomIv = RandomNumberGenerator.GetBytes(12);
	}

	private static void Test(IStreamCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (int i = 0; i < 1000; ++i)
		{
			crypto.Update(origin, o);
		}

		crypto.Dispose();
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Test(new BcChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark]
	public void SoftwareFallback()
	{
		Test(new ChaCha20CryptoSF(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark(Baseline = true)]
	public void X86()
	{
		Test(new ChaCha20CryptoX86(_randomKey, _randomIv), _randombytes.Span);
	}
}
