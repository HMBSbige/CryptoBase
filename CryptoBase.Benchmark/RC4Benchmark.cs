using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class RC4Benchmark
{
	[Params(1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = Utils.RandBytes(ByteLength).ToArray();
		_randomKey = Utils.RandBytes(16).ToArray();
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
		Test(new BcRC4Crypto(_randomKey), _randombytes.Span);
	}

	[Benchmark(Baseline = true)]
	public void RC4()
	{
		Test(StreamCryptoCreate.Rc4(_randomKey), _randombytes.Span);
	}
}
