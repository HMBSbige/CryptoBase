using BenchmarkDotNet.Attributes;
using CryptoBase.Digests;
using CryptoBase.KDF;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class HKDFBenchmark
{
	[Params(32, 82)]
	public int OutputLength { get; set; }

	private byte[] _ikm = null!;
	private byte[] _salt = null!;
	private byte[] _info = null!;
	private byte[] _output = null!;

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(80);
		_salt = RandomNumberGenerator.GetBytes(80);
		_info = RandomNumberGenerator.GetBytes(80);
		_output = new byte[OutputLength];
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		Hkdf.DeriveKey(DigestType.Sha256, _ikm, _output, _salt, _info);
	}

	[Benchmark]
	public void DotNet()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA256, _ikm, _output, _salt, _info);
	}
}
