using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class CFBBenchmark
{
	[Params(1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey16 = null!;
	private byte[] _randomIv8 = null!;
	private byte[] _randomIv16 = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
		_randomKey16 = RandomNumberGenerator.GetBytes(16);
		_randomIv8 = RandomNumberGenerator.GetBytes(8);
		_randomIv16 = RandomNumberGenerator.GetBytes(16);
	}

	private static void Test(IStreamCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];
		crypto.Update(origin, o);

		crypto.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void ChaCha20()
	{
		Test(new ChaCha20OriginalCryptoX86(_randomKey16, _randomIv8), _randombytes.Span);
	}

	[Benchmark]
	public void AESCFB()
	{
		Test(StreamCryptoCreate.AesCfb(true, _randomKey16, _randomIv16), _randombytes.Span);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Test(new BcAESCFBStreamCrypto(true, _randomKey16, _randomIv16), _randombytes.Span);
	}
}
