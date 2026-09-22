using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using CryptoBase.Ciphers.Blocks.Aes;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Benchmark.Ciphers.Blocks.Aes;

[MemoryDiagnoser]
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
					.WithEnvironmentVariable("DOTNET_EnableAVX", "0")
					.WithLaunchCount(1)
					.WithWarmupCount(3)
					.WithIterationCount(8)
			);
		}
	}

	[Params(16, 32)]
	public int KeyLength { get; set; }

	[Params(16, 128, 1024)]
	public int ByteLength { get; set; }

	[Params(false, true)]
	public bool IsDecrypt { get; set; }

	private AesCipherSoftware _software;
	private AesCipherVpaes _vpaes;
	private AesCipherBitslice _bitslice;
	private byte[] _source = [];
	private byte[] _destination = [];

	[GlobalSetup]
	public void Setup()
	{
		if (!Ssse3.IsSupported || Avx.IsSupported)
		{
			throw new InvalidOperationException("Expected SSSE3 without AVX.");
		}

		byte[] key = RandomNumberGenerator.GetBytes(KeyLength);
		_software = AesCipherSoftware.Create(key);
		_vpaes = AesCipherVpaes.Create(key);
		_bitslice = AesCipherBitslice.Create(key);
		_source = RandomNumberGenerator.GetBytes(ByteLength);
		_destination = new byte[ByteLength];

		using BclAes reference = BclAes.Create();
		reference.Key = key;
		byte[] expected = IsDecrypt
			? reference.DecryptEcb(_source, PaddingMode.None)
			: reference.EncryptEcb(_source, PaddingMode.None);

		Bitslice();
		Check(expected, nameof(Bitslice));
		Vpaes();
		Check(expected, nameof(Vpaes));
		SimdBitslice();
		Check(expected, nameof(SimdBitslice));
	}

	private void Check(byte[] expected, string backend)
	{
		if (!expected.AsSpan().SequenceEqual(_destination))
		{
			throw new InvalidOperationException($"{backend} AES output differs from BCL.");
		}

		_destination.AsSpan().Fill(0xCC);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_software.Dispose();
		_vpaes.Dispose();
		_bitslice.Dispose();
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

	[Benchmark]
	public void SimdBitslice()
	{
		if (IsDecrypt)
		{
			_bitslice.DecryptBlocks(_source, _destination);
		}
		else
		{
			_bitslice.EncryptBlocks(_source, _destination);
		}
	}
}
