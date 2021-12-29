using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SodiumIncrementBenchmark
{
	[Params(1, 10000)]
	public int Max { get; set; }

	private byte[] _randombytes = null!;
	private byte[] _randombytes2 = null!;
	private byte[] _randombytes3 = null!;
	private byte[] _randombytes4 = null!;
	private byte[] _randombytes16 = null!;

	private IBlockCrypto _aes = null!;
	private readonly Memory<byte> _buffer = new byte[16];

	[GlobalSetup]
	public void Setup()
	{
		var random = Utils.RandBytes(4);
		_randombytes = random.ToArray();
		_randombytes2 = random.ToArray();
		_randombytes3 = random.ToArray();
		_randombytes4 = random.ToArray();
		_randombytes16 = Utils.RandBytes(16).ToArray();
		_aes = AESUtils.CreateECB(_randombytes16);
	}

	[Benchmark(Baseline = true)]
	public void Increment()
	{
		for (var i = 0; i < Max; ++i)
		{
			_randombytes.Increment();
			_aes.Encrypt(_randombytes16, _buffer.Span);
			_randombytes.Increment();
			_aes.Decrypt(_randombytes16, _buffer.Span);
		}
	}

	[Benchmark]
	public void IncrementUInt()
	{
		for (var i = 0; i < Max; ++i)
		{
			_randombytes2.IncrementUInt();
			_aes.Encrypt(_randombytes16, _buffer.Span);
			_randombytes2.IncrementUInt();
			_aes.Decrypt(_randombytes16, _buffer.Span);
		}
	}

	[Benchmark]
	public void IncrementIntUnsafe()
	{
		for (var i = 0; i < Max; ++i)
		{
			_randombytes3.IncrementIntUnsafe();
			_aes.Encrypt(_randombytes16, _buffer.Span);
			_randombytes3.IncrementIntUnsafe();
			_aes.Decrypt(_randombytes16, _buffer.Span);
		}
	}

	[Benchmark]
	public void IncrementSource()
	{
		for (var i = 0; i < Max; ++i)
		{
			_randombytes4.IncrementSource();
			_aes.Encrypt(_randombytes16, _buffer.Span);
			_randombytes4.IncrementSource();
			_aes.Decrypt(_randombytes16, _buffer.Span);
		}
	}
}
