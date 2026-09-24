using BenchmarkDotNet.Attributes;
using System.Runtime.Intrinsics;
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

	[GlobalSetup]
	public void Setup()
	{
		_keyBytes = RandomNumberGenerator.GetBytes(GHashAlgorithmCore.BlockSizeInBytes);
		_key = GHashKeyCore.Create(_keyBytes);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
	}

	[Benchmark]
	public Vector128<byte> CryptoBase()
	{
		using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref _key);
		return hash.Finish(_input, default, default);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_key.Dispose();
		CryptographicOperations.ZeroMemory(_keyBytes);
	}

	[Benchmark]
	public Vector128<byte> ColdKey()
	{
		GHashKeyCore key = GHashKeyCore.Create(_keyBytes);

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref key);
			return hash.Finish(_input, default, default);
		}
		finally
		{
			key.Dispose();
		}
	}
}
