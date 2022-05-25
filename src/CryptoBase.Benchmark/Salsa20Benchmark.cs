using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class Salsa20Benchmark
{
	[Params(1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;
	private byte[] _randomIv = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
		_randomKey = RandomNumberGenerator.GetBytes(32);
		_randomIv = RandomNumberGenerator.GetBytes(8);
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
		Test(new BcSalsa20Crypto(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark]
	public void SoftwareFallback()
	{
		Test(new Salsa20CryptoSF(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark(Baseline = true)]
	public void X86()
	{
		Test(new Salsa20CryptoX86(_randomKey, _randomIv), _randombytes.Span);
	}
}
