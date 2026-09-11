using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;
using GHashAlgorithmCore = CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm.GHash;

namespace CryptoBase.Benchmark.SymmetricCryptos.BlockCryptoModes.Gcm;

[MemoryDiagnoser]
public class GHashBenchmark
{
	[Params(16, 128, 256, 512, 8192)]
	public int ByteLength { get; set; }

	private byte[] _key = [];
	private byte[] _input = [];
	private byte[] _hash = [];
	private GHashAlgorithmCore _gHash;

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(GHashAlgorithmCore.BlockSizeInBytes);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		_gHash = GHashAlgorithmCore.Create(_key);
	}

	[Benchmark]
	public int CryptoBase()
	{
		return _gHash.HashPaddedSegmentsAndReset(_input, default, default, _hash);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_gHash.ZeroMemory();
	}
}
