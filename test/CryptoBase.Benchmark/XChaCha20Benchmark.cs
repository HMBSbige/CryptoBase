using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XChaCha20Benchmark
{
	[Params(32, 1000000)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;
	private byte[] _randomIv = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
		_randomKey = RandomNumberGenerator.GetBytes(32);
		_randomIv = RandomNumberGenerator.GetBytes(24);
	}

	private static void Test(IStreamCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];
		crypto.Update(origin, o);

		crypto.Dispose();
	}

	[Benchmark]
	public void SoftwareFallback()
	{
		Test(new XChaCha20CryptoSF(_randomKey, _randomIv), _randombytes.Span);
	}

	[Benchmark(Baseline = true)]
	public void X86()
	{
		Test(new XChaCha20CryptoX86(_randomKey, _randomIv), _randombytes.Span);
	}
}
