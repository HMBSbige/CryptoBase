using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using CryptoBase.Ciphers.Blocks.Aes;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Benchmark.Ciphers.Blocks.Aes;

[MemoryDiagnoser]
[RankColumn]
[Config(typeof(NoAvxConfig))]
public class AesSoftwareBackendBenchmark
{
	private sealed class NoAvxConfig : ManualConfig
	{
		public NoAvxConfig()
		{
			AddJob
			(
				Job.Default
					.WithEnvironmentVariable(@"DOTNET_EnableAVX", @"0")
					.WithLaunchCount(1)
					.WithWarmupCount(3)
					.WithIterationCount(8)
			);
		}
	}

	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(16, 32, 48, 64)]
	public int ByteLength { get; set; }

	[Params(false, true)]
	public bool IsDecrypt { get; set; }

	private AesCipherVpaes _vpaes;
	private AesCipherSoftware _software;
	private byte[] _source = [];
	private byte[] _destination = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(KeyLength);
		_vpaes = AesCipherVpaes.Create(key);
		_software = AesCipherSoftware.Create(key);

		_source = RandomNumberGenerator.GetBytes(ByteLength);
		_destination = new byte[ByteLength];

		using BclAes reference = BclAes.Create();
		reference.Key = key;
		byte[] expected = IsDecrypt
			? reference.DecryptEcb(_source, PaddingMode.None)
			: reference.EncryptEcb(_source, PaddingMode.None);

		Vpaes();

		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException("VPAES AES output differs from BCL.");
		}

		Bitslice();

		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException("Bitsliced AES output differs from BCL.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_vpaes.Dispose();
		_software.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void Bitslice()
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
	public void Vpaes()
	{
		if (IsDecrypt)
		{
			_vpaes.DecryptBlocks(_source, _destination);
		}
		else
		{
			_vpaes.EncryptBlocks(_source, _destination);
		}
	}
}
