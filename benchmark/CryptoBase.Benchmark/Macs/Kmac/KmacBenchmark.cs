using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Macs.Kmac;
using System.Security.Cryptography;
using BouncyCastleKeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using BouncyCastleKmac = Org.BouncyCastle.Crypto.Macs.KMac;

namespace CryptoBase.Benchmark.Macs.Kmac;

// The customization string of the NIST KMAC samples, with outputs of twice the security strength. Incremental creates an instance per operation; Reuse keeps one, which each operation resets to its key.
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class KmacBenchmark
{
	private const int MaxInputLength = 1024 * 1024;
	private const int KeyLength = 32;
	private const int Kmac128OutputLength = 32;
	private const int Kmac256OutputLength = 64;

	private static readonly byte[] Customization = "My Tagged Application"u8.ToArray();

	private byte[] _key = [];
	private byte[] _input = [];
	private byte[] _mac = [];

	private Kmac128Algorithm _kmac128 = Kmac128Algorithm.Create([]);
	private Kmac256Algorithm _kmac256 = Kmac256Algorithm.Create([]);

	// Where the platform lacks KMAC, these stay null and the BCL columns throw PlatformNotSupportedException, while the other columns still run.
	private Kmac128? _bclKmac128;
	private Kmac256? _bclKmac256;

	[Params(0, 64, 1024, 8192, MaxInputLength)]
	public int InputLength { get; set; }

	private Kmac128 BclKmac128 => _bclKmac128 ?? throw new PlatformNotSupportedException();

	private Kmac256 BclKmac256 => _bclKmac256 ?? throw new PlatformNotSupportedException();

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(KeyLength);
		_input = RandomNumberGenerator.GetBytes(InputLength);
		_mac = new byte[Kmac256OutputLength];

		_kmac128.Dispose();
		_kmac256.Dispose();
		_kmac128 = Kmac128Algorithm.Create(_key, Customization);
		_kmac256 = Kmac256Algorithm.Create(_key, Customization);

		if (Kmac128.IsSupported)
		{
			_bclKmac128?.Dispose();
			_bclKmac256?.Dispose();
			_bclKmac128 = new Kmac128(_key, Customization);
			_bclKmac256 = new Kmac256(_key, Customization);
		}

		Kmac128BouncyCastle();
		byte[] expected = _mac.AsSpan(0, Kmac128OutputLength).ToArray();
		Verify(expected, Kmac128CryptoBase, Kmac128CryptoBaseIncremental, Kmac128CryptoBaseReuse, Kmac128CryptoBaseReuseCurrent);
		VerifyBcl(expected, Kmac128Bcl, Kmac128BclIncremental, Kmac128BclReuse);

		Kmac256BouncyCastle();
		expected = _mac.AsSpan(0, Kmac256OutputLength).ToArray();
		Verify(expected, Kmac256CryptoBase, Kmac256CryptoBaseIncremental, Kmac256CryptoBaseReuse, Kmac256CryptoBaseReuseCurrent);
		VerifyBcl(expected, Kmac256Bcl, Kmac256BclIncremental, Kmac256BclReuse);

		KmacXof128BouncyCastle();
		expected = _mac.AsSpan(0, Kmac128OutputLength).ToArray();
		Verify(expected, KmacXof128CryptoBase);
		VerifyBcl(expected, KmacXof128Bcl);

		KmacXof256BouncyCastle();
		expected = _mac.AsSpan(0, Kmac256OutputLength).ToArray();
		Verify(expected, KmacXof256CryptoBase);
		VerifyBcl(expected, KmacXof256Bcl);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_kmac128.Dispose();
		_kmac256.Dispose();
		_bclKmac128?.Dispose();
		_bclKmac256?.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMAC128")]
	public void Kmac128Bcl()
	{
		Kmac128.HashData(_key, _input, _mac.AsSpan(0, Kmac128OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMAC128")]
	public void Kmac128CryptoBase()
	{
		Kmac128Algorithm.Mac(_key, _input, _mac.AsSpan(0, Kmac128OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMAC128")]
	public int Kmac128BouncyCastle()
	{
		return BouncyCastleMac(128, Kmac128OutputLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMAC256")]
	public void Kmac256Bcl()
	{
		Kmac256.HashData(_key, _input, _mac.AsSpan(0, Kmac256OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMAC256")]
	public void Kmac256CryptoBase()
	{
		Kmac256Algorithm.Mac(_key, _input, _mac.AsSpan(0, Kmac256OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMAC256")]
	public int Kmac256BouncyCastle()
	{
		return BouncyCastleMac(256, Kmac256OutputLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMAC128-Incremental")]
	public void Kmac128BclIncremental()
	{
		using Kmac128 kmac = new(_key, Customization);
		kmac.AppendData(_input);
		kmac.GetHashAndReset(_mac.AsSpan(0, Kmac128OutputLength));
	}

	[Benchmark]
	[BenchmarkCategory("KMAC128-Incremental")]
	public void Kmac128CryptoBaseIncremental()
	{
		using Kmac128Algorithm kmac = Kmac128Algorithm.Create(_key, Customization);
		kmac.Append(_input);
		kmac.GetMacAndReset(_mac.AsSpan(0, Kmac128OutputLength));
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMAC256-Incremental")]
	public void Kmac256BclIncremental()
	{
		using Kmac256 kmac = new(_key, Customization);
		kmac.AppendData(_input);
		kmac.GetHashAndReset(_mac.AsSpan(0, Kmac256OutputLength));
	}

	[Benchmark]
	[BenchmarkCategory("KMAC256-Incremental")]
	public void Kmac256CryptoBaseIncremental()
	{
		using Kmac256Algorithm kmac = Kmac256Algorithm.Create(_key, Customization);
		kmac.Append(_input);
		kmac.GetMacAndReset(_mac.AsSpan(0, Kmac256OutputLength));
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMAC128-Reuse")]
	public void Kmac128BclReuse()
	{
		Kmac128 kmac = BclKmac128;
		kmac.AppendData(_input);
		kmac.GetHashAndReset(_mac.AsSpan(0, Kmac128OutputLength));
	}

	[Benchmark]
	[BenchmarkCategory("KMAC128-Reuse")]
	public void Kmac128CryptoBaseReuse()
	{
		_kmac128.Append(_input);
		_kmac128.GetMacAndReset(_mac.AsSpan(0, Kmac128OutputLength));
	}

	[Benchmark]
	[BenchmarkCategory("KMAC128-Reuse")]
	public void Kmac128CryptoBaseReuseCurrent()
	{
		_kmac128.Append(_input);
		_kmac128.GetCurrentMac(_mac.AsSpan(0, Kmac128OutputLength));
		_kmac128.Reset();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMAC256-Reuse")]
	public void Kmac256BclReuse()
	{
		Kmac256 kmac = BclKmac256;
		kmac.AppendData(_input);
		kmac.GetHashAndReset(_mac.AsSpan(0, Kmac256OutputLength));
	}

	[Benchmark]
	[BenchmarkCategory("KMAC256-Reuse")]
	public void Kmac256CryptoBaseReuse()
	{
		_kmac256.Append(_input);
		_kmac256.GetMacAndReset(_mac.AsSpan(0, Kmac256OutputLength));
	}

	[Benchmark]
	[BenchmarkCategory("KMAC256-Reuse")]
	public void Kmac256CryptoBaseReuseCurrent()
	{
		_kmac256.Append(_input);
		_kmac256.GetCurrentMac(_mac.AsSpan(0, Kmac256OutputLength));
		_kmac256.Reset();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMACXOF128")]
	public void KmacXof128Bcl()
	{
		KmacXof128.HashData(_key, _input, _mac.AsSpan(0, Kmac128OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMACXOF128")]
	public void KmacXof128CryptoBase()
	{
		KmacXof128Algorithm.HashData(_key, _input, _mac.AsSpan(0, Kmac128OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMACXOF128")]
	public int KmacXof128BouncyCastle()
	{
		return BouncyCastleXof(128, Kmac128OutputLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KMACXOF256")]
	public void KmacXof256Bcl()
	{
		KmacXof256.HashData(_key, _input, _mac.AsSpan(0, Kmac256OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMACXOF256")]
	public void KmacXof256CryptoBase()
	{
		KmacXof256Algorithm.HashData(_key, _input, _mac.AsSpan(0, Kmac256OutputLength), Customization);
	}

	[Benchmark]
	[BenchmarkCategory("KMACXOF256")]
	public int KmacXof256BouncyCastle()
	{
		return BouncyCastleXof(256, Kmac256OutputLength);
	}

	// OutputFinal encodes the requested length, as KMAC does; Output encodes 0, as KMACXOF does.
	private int BouncyCastleMac(int securityStrength, int outputLength)
	{
		BouncyCastleKmac kmac = new(securityStrength, Customization);
		kmac.Init(new BouncyCastleKeyParameter(_key));
		kmac.BlockUpdate(_input);
		return kmac.OutputFinal(_mac.AsSpan(0, outputLength));
	}

	private int BouncyCastleXof(int securityStrength, int outputLength)
	{
		BouncyCastleKmac kmac = new(securityStrength, Customization);
		kmac.Init(new BouncyCastleKeyParameter(_key));
		kmac.BlockUpdate(_input);
		return kmac.Output(_mac.AsSpan(0, outputLength));
	}

	private void VerifyBcl(ReadOnlySpan<byte> expected, params ReadOnlySpan<Action> implementations)
	{
		if (Kmac128.IsSupported)
		{
			Verify(expected, implementations);
		}
	}

	private void Verify(ReadOnlySpan<byte> expected, params ReadOnlySpan<Action> implementations)
	{
		foreach (Action implementation in implementations)
		{
			_mac.AsSpan().Clear();
			implementation();

			if (!CryptographicOperations.FixedTimeEquals(expected, _mac.AsSpan(0, expected.Length)))
			{
				throw new InvalidOperationException($"{implementation.Method.Name} produced different output.");
			}
		}
	}
}
