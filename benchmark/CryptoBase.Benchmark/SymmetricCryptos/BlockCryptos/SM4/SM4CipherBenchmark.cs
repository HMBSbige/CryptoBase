using BenchmarkDotNet.Attributes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.SymmetricCryptos.BlockCryptos.SM4;

[MemoryDiagnoser]
[RankColumn]
public class SM4CipherBenchmark
{
	[Params(16, 128, 256, 512, 1024, 8192)]
	public int ByteLength { get; set; }

	[Params(false, true)]
	public bool IsDecrypt { get; set; }

	private SM4Cipher _cipher = default!;
	private SM4Engine _bcEncryptionEngine = default!;
	private SM4Engine _bcDecryptionEngine = default!;
	private byte[] _source = [];
	private byte[] _destination = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		_cipher = SM4Cipher.Create(key);

		KeyParameter keyParameter = new(key);
		_bcEncryptionEngine = new SM4Engine();
		_bcDecryptionEngine = new SM4Engine();
		_bcEncryptionEngine.Init(true, keyParameter);
		_bcDecryptionEngine.Init(false, keyParameter);

		_source = RandomNumberGenerator.GetBytes(ByteLength);
		_destination = new byte[ByteLength];

		byte[] expected = new byte[ByteLength];
		BouncyCastleCore(expected);
		BlockCipherBenchmarkUtils.Transform(_cipher, IsDecrypt, _source, _destination);

		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException("CryptoBase SM4 output differs from BouncyCastle.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cipher.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		BlockCipherBenchmarkUtils.Transform(_cipher, IsDecrypt, _source, _destination);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		BouncyCastleCore(_destination);
	}

	private void BouncyCastleCore(Span<byte> destination)
	{
		SM4Engine engine = IsDecrypt ? _bcDecryptionEngine : _bcEncryptionEngine;
		ReadOnlySpan<byte> source = _source;

		for (int offset = 0; offset < source.Length; offset += 16)
		{
			engine.ProcessBlock(source.Slice(offset, 16), destination.Slice(offset, 16));
		}
	}
}
