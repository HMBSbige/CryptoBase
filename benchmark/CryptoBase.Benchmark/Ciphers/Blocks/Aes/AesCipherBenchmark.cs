using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Blocks.Aes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Benchmark.Ciphers.Blocks.Aes;

[MemoryDiagnoser]
[RankColumn]
public class AesCipherBenchmark
{
	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(16, 64, 80, 128, 256, 512, 1024, 8192)]
	public int ByteLength { get; set; }

	[Params(false, true)]
	public bool IsDecrypt { get; set; }

	private AesCipher _cipher = default!;
	private AesCipherSoftware _software;
	private BclAes _bcl = default!;
	private IBlockCipher _bcEncryptionEngine = default!;
	private IBlockCipher _bcDecryptionEngine = default!;
	private byte[] _source = [];
	private byte[] _destination = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(KeyLength);
		_cipher = AesCipher.Create(key);
		_software = AesCipherSoftware.Create(key);

		_bcl = BclAes.Create();
		_bcl.Key = key;

		KeyParameter keyParameter = new(key);
		_bcEncryptionEngine = AesUtilities.CreateEngine();
		_bcDecryptionEngine = AesUtilities.CreateEngine();
		_bcEncryptionEngine.Init(true, keyParameter);
		_bcDecryptionEngine.Init(false, keyParameter);

		_source = RandomNumberGenerator.GetBytes(ByteLength);
		_destination = new byte[ByteLength];

		byte[] expected = new byte[ByteLength];
		BclCore(expected);
		BlockCipherBenchmarkUtils.Transform(_cipher, IsDecrypt, _source, _destination);

		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException("CryptoBase AES output differs from BCL.");
		}

		CryptoBaseSoftware();

		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException("CryptoBase scalar AES output differs from BCL.");
		}

		BouncyCastleCore(_destination);

		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException("BouncyCastle AES output differs from BCL.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cipher.Dispose();
		_software.Dispose();
		_bcl.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		BlockCipherBenchmarkUtils.Transform(_cipher, IsDecrypt, _source, _destination);
	}

	[Benchmark]
	public void CryptoBaseSoftware()
	{
		if (IsDecrypt)
		{
			_software.DecryptBlocks(_source, _destination);
		}
		else
		{
			_software.EncryptBlocks(_source, _destination);
		}
	}

	[Benchmark]
	public void Bcl()
	{
		BclCore(_destination);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		BouncyCastleCore(_destination);
	}

	private void BclCore(Span<byte> destination)
	{
		if (IsDecrypt)
		{
			_bcl.DecryptEcb(_source, destination, PaddingMode.None);
		}
		else
		{
			_bcl.EncryptEcb(_source, destination, PaddingMode.None);
		}
	}

	private void BouncyCastleCore(Span<byte> destination)
	{
		IBlockCipher engine = IsDecrypt ? _bcDecryptionEngine : _bcEncryptionEngine;
		ReadOnlySpan<byte> source = _source;

		for (int offset = 0; offset < source.Length; offset += 16)
		{
			engine.ProcessBlock(source.Slice(offset, 16), destination.Slice(offset, 16));
		}
	}
}
