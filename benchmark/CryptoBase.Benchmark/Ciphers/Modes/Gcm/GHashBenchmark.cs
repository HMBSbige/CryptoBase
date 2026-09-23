using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;
using GHashAlgorithmCore = CryptoBase.Ciphers.Modes.Gcm.GHash;
using GHashKeyCore = CryptoBase.Ciphers.Modes.Gcm.GHashKey;

namespace CryptoBase.Benchmark.Ciphers.Modes.Gcm;

[MemoryDiagnoser]
public class GHashBenchmark
{
	[Params(16, 128, 256, 512, 8192)]
	public int ByteLength { get; set; }

	private GHashKeyCore _key;
	private byte[] _keyBytes = [];
	private byte[] _input = [];
	private byte[] _hash = [];

	[GlobalSetup]
	public void Setup()
	{
		_keyBytes = RandomNumberGenerator.GetBytes(GHashAlgorithmCore.BlockSizeInBytes);
		_key = GHashKeyCore.Create(_keyBytes);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[GHashAlgorithmCore.BlockSizeInBytes];
	}

	[Benchmark]
	public int CryptoBase()
	{
		using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref _key);
		return hash.HashPaddedSegmentsAndReset(_input, default, default, _hash);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_key.Dispose();
		CryptographicOperations.ZeroMemory(_keyBytes);
	}

	[Benchmark]
	public int ColdKey()
	{
		GHashKeyCore key = GHashKeyCore.Create(_keyBytes);

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref key);
			return hash.HashPaddedSegmentsAndReset(_input, default, default, _hash);
		}
		finally
		{
			key.Dispose();
		}
	}
}
