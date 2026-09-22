using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using CryptoBase.Ciphers.Blocks.Aes;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Benchmark.Ciphers.Blocks.Aes;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[Config(typeof(SoftwareOnlyConfig))]
public class AesSoftwareBackendBenchmark
{
	private sealed class SoftwareOnlyConfig : ManualConfig
	{
		public SoftwareOnlyConfig()
		{
			AddJob(Job.Default.WithEnvironmentVariable("DOTNET_EnableAES", "0").WithEnvironmentVariable("DOTNET_EnableArm64Aes", "0").WithEnvironmentVariable("DOTNET_EnableAVX", "0").AsMutator());
		}
	}

	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(16, 32, 48, 64, 128, 1024)]
	public int ByteLength { get; set; }

	private AesCipherSoftware _scalar;
	private AesCipher _autoSoftware = null!;
	private byte[] _source = [];
	private byte[] _destination = [];

	[GlobalSetup]
	public void Setup()
	{
		if (AesCipherX86.IsSupported || AesCipherArm.IsSupported || Avx.IsSupported)
		{
			throw new InvalidOperationException("Hardware AES and AVX must be disabled in the benchmark process.");
		}

		byte[] key = RandomNumberGenerator.GetBytes(KeyLength);
		_scalar = AesCipherSoftware.Create(key);
		_autoSoftware = AesCipher.Create(key);
		_source = RandomNumberGenerator.GetBytes(ByteLength);
		_destination = new byte[ByteLength];

		using BclAes reference = BclAes.Create();
		reference.Key = key;
		byte[] encrypted = reference.EncryptEcb(_source, PaddingMode.None);
		byte[] decrypted = reference.DecryptEcb(_source, PaddingMode.None);

		ScalarEncrypt();
		Check(encrypted, nameof(ScalarEncrypt));
		AutoSoftwareEncrypt();
		Check(encrypted, nameof(AutoSoftwareEncrypt));
		ScalarDecrypt();
		Check(decrypted, nameof(ScalarDecrypt));
		AutoSoftwareDecrypt();
		Check(decrypted, nameof(AutoSoftwareDecrypt));
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
		_scalar.Dispose();
		_autoSoftware.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Encrypt")]
	public void ScalarEncrypt()
	{
		_scalar.EncryptBlocks(_source, _destination);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public void AutoSoftwareEncrypt()
	{
		_autoSoftware.EncryptBlocks(_source, _destination);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decrypt")]
	public void ScalarDecrypt()
	{
		_scalar.DecryptBlocks(_source, _destination);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public void AutoSoftwareDecrypt()
	{
		_autoSoftware.DecryptBlocks(_source, _destination);
	}
}
