using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Blake3;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Blake3;

[MemoryDiagnoser]
public class Blake3Benchmark
{
	private readonly Blake3Digest _bouncyCastle = new();
	private readonly byte[] _hash = new byte[Blake3HashAlgorithm.HashLength];
	private byte[] _input = [];

	[Params(0, 64, 65, 1024, 1025, 2048, 4096, 8192, 16 * 1024, 64 * 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);

		BouncyCastle();
		byte[] expected = (byte[])_hash.Clone();
		CryptoBase();

		if (!CryptographicOperations.FixedTimeEquals(expected, _hash))
		{
			throw new InvalidOperationException("Benchmark implementations produced different hashes.");
		}
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Blake3HashAlgorithm.HashData(_input, _hash);
	}

	[Benchmark]
	public int BouncyCastle()
	{
		_bouncyCastle.BlockUpdate(_input);
		return _bouncyCastle.DoFinal(_hash);
	}
}
