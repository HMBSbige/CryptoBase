using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kdf;

public class HkdfSha1Benchmark() : HkdfBenchmarkBase<Sha1Core>(HashAlgorithmName.SHA1);

public class HkdfSha256Benchmark() : HkdfBenchmarkBase<Sha256Core>(HashAlgorithmName.SHA256)
{
	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int GenericExtract()
	{
		return Hkdf<HmacAlgorithm<Sha256Core>>.Extract(Ikm, Salt, Prk);
	}

	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int PlatformExtract()
	{
		return Hkdf<PlatformHmacSha256>.Extract(Ikm, Salt, Prk);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void GenericDeriveKey()
	{
		Hkdf<HmacAlgorithm<Sha256Core>>.DeriveKey(Ikm, Output, Salt, Info);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void PlatformDeriveKey()
	{
		Hkdf<PlatformHmacSha256>.DeriveKey(Ikm, Output, Salt, Info);
	}
}

public class HkdfSha384Benchmark() : HkdfBenchmarkBase<Sha384Core>(HashAlgorithmName.SHA384);

public class HkdfSha512Benchmark() : HkdfBenchmarkBase<Sha512Core>(HashAlgorithmName.SHA512);

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class HkdfBenchmarkBase<TCore>(HashAlgorithmName hashAlgorithm) where TCore : unmanaged, IHmacHashCore<TCore>
{
	[ParamsSource(nameof(ByteLengths))]
	public int ByteLength { get; set; }

	// Around one and two HMAC blocks, then long inputs; for 128-byte blocks two blocks are the 256 bytes listed anyway.
	public IEnumerable<int> ByteLengths => new[] { 0, 1, TCore.HmacBlockSize - 1, TCore.HmacBlockSize, TCore.HmacBlockSize + 1, 2 * TCore.HmacBlockSize, 256, 1024, 8192, 1024 * 1024 }.Distinct();

	private byte[] _ikm = [];
	private byte[] _salt = [];
	private byte[] _info = [];
	private byte[] _prk = [];
	private byte[] _output = [];

	protected ReadOnlySpan<byte> Ikm => _ikm;

	protected ReadOnlySpan<byte> Salt => _salt;

	protected ReadOnlySpan<byte> Info => _info;

	protected Span<byte> Prk => _prk;

	protected Span<byte> Output => _output;

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(ByteLength);
		_salt = RandomNumberGenerator.GetBytes(TCore.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_prk = new byte[HashAlgorithm<TCore>.HashLength];
		_output = new byte[2 * HashAlgorithm<TCore>.HashLength + 1];
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Extract")]
	public int BclExtract()
	{
		return HKDF.Extract(hashAlgorithm, _ikm, _salt, _prk);
	}

	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int CryptoBaseExtract()
	{
		return Hkdf.Extract<TCore>(_ikm, _salt, _prk);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("DeriveKey")]
	public void BclDeriveKey()
	{
		HKDF.DeriveKey(hashAlgorithm, _ikm, _output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void CryptoBaseDeriveKey()
	{
		Hkdf.DeriveKey<TCore>(_ikm, _output, _salt, _info);
	}
}

[MemoryDiagnoser]
public class Hkdf64BlockCountBenchmark
{
	[Params(1, 3, 16, 255)]
	public int BlockCount { get; set; }

	private byte[] _ikm = [];
	private byte[] _salt = [];
	private byte[] _info = [];
	private byte[] _output = [];

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(256);
		_salt = RandomNumberGenerator.GetBytes(Sha256Core.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_output = new byte[BlockCount * HashAlgorithm<Sha256Core>.HashLength];
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Hkdf.DeriveKey<Sha256Core>(_ikm, _output, _salt, _info);
	}

	[Benchmark]
	public void Bcl()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA256, _ikm, _output, _salt, _info);
	}

	[Benchmark]
	public void Generic()
	{
		Hkdf<HmacAlgorithm<Sha256Core>>.DeriveKey(_ikm, _output, _salt, _info);
	}

	[Benchmark]
	public void Platform()
	{
		Hkdf<PlatformHmacSha256>.DeriveKey(_ikm, _output, _salt, _info);
	}
}

// The shape of a TLS 1.3 key schedule step with SHA-256: a 32-byte secret and salt, and a 32-byte output from an HkdfLabel of about 50 bytes.
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class HkdfTls13Benchmark
{
	private byte[] _ikm = [];
	private byte[] _salt = [];
	private byte[] _info = [];
	private byte[] _prk = [];
	private byte[] _output = [];

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(32);
		_salt = RandomNumberGenerator.GetBytes(32);
		_info = RandomNumberGenerator.GetBytes(50);
		_prk = new byte[HashAlgorithm<Sha256Core>.HashLength];
		_output = new byte[32];

		BclExtract();
		byte[] expectedPrk = (byte[])_prk.Clone();
		VerifyExtract(expectedPrk, CryptoBaseExtract);
		VerifyExtract(expectedPrk, GenericExtract);
		VerifyExtract(expectedPrk, PlatformExtract);

		BclExpand();
		byte[] expectedExpand = (byte[])_output.Clone();
		VerifyOutput(expectedExpand, CryptoBaseExpand);
		VerifyOutput(expectedExpand, GenericExpand);
		VerifyOutput(expectedExpand, PlatformExpand);

		BclDeriveKey();
		byte[] expectedDeriveKey = (byte[])_output.Clone();
		VerifyOutput(expectedDeriveKey, CryptoBaseDeriveKey);
		VerifyOutput(expectedDeriveKey, GenericDeriveKey);
		VerifyOutput(expectedDeriveKey, PlatformDeriveKey);
	}

	private void VerifyExtract(byte[] expected, Func<int> extract)
	{
		_prk.AsSpan().Clear();
		extract();
		Verify(expected, _prk);
	}

	private void VerifyOutput(byte[] expected, Action derive)
	{
		_output.AsSpan().Clear();
		derive();
		Verify(expected, _output);
	}

	private static void Verify(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
	{
		if (!CryptographicOperations.FixedTimeEquals(expected, actual))
		{
			throw new InvalidOperationException("Benchmark implementations produced different keys.");
		}
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Extract")]
	public int BclExtract()
	{
		return HKDF.Extract(HashAlgorithmName.SHA256, _ikm, _salt, _prk);
	}

	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int CryptoBaseExtract()
	{
		return Hkdf.Extract<Sha256Core>(_ikm, _salt, _prk);
	}

	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int GenericExtract()
	{
		return Hkdf<HmacAlgorithm<Sha256Core>>.Extract(_ikm, _salt, _prk);
	}

	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int PlatformExtract()
	{
		return Hkdf<PlatformHmacSha256>.Extract(_ikm, _salt, _prk);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Expand")]
	public void BclExpand()
	{
		HKDF.Expand(HashAlgorithmName.SHA256, _prk, _output, _info);
	}

	[Benchmark]
	[BenchmarkCategory("Expand")]
	public void CryptoBaseExpand()
	{
		Hkdf.Expand<Sha256Core>(_prk, _output, _info);
	}

	[Benchmark]
	[BenchmarkCategory("Expand")]
	public void GenericExpand()
	{
		Hkdf<HmacAlgorithm<Sha256Core>>.Expand(_prk, _output, _info);
	}

	[Benchmark]
	[BenchmarkCategory("Expand")]
	public void PlatformExpand()
	{
		Hkdf<PlatformHmacSha256>.Expand(_prk, _output, _info);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("DeriveKey")]
	public void BclDeriveKey()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA256, _ikm, _output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void CryptoBaseDeriveKey()
	{
		Hkdf.DeriveKey<Sha256Core>(_ikm, _output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void GenericDeriveKey()
	{
		Hkdf<HmacAlgorithm<Sha256Core>>.DeriveKey(_ikm, _output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void PlatformDeriveKey()
	{
		Hkdf<PlatformHmacSha256>.DeriveKey(_ikm, _output, _salt, _info);
	}
}

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Hkdf128BlockCountBenchmark
{
	[Params(1, 3, 4, 16, 255)]
	public int BlockCount { get; set; }

	private byte[] _ikm = [];
	private byte[] _salt = [];
	private byte[] _info = [];
	private byte[] _sha384Output = [];
	private byte[] _sha512Output = [];

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(256);
		_salt = RandomNumberGenerator.GetBytes(Sha512Core.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_sha384Output = new byte[BlockCount * HashAlgorithm<Sha384Core>.HashLength];
		_sha512Output = new byte[BlockCount * HashAlgorithm<Sha512Core>.HashLength];
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-384")]
	public void CryptoBaseSha384()
	{
		Hkdf.DeriveKey<Sha384Core>(_ikm, _sha384Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-384")]
	public void BclSha384()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA384, _ikm, _sha384Output, _salt, _info);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-512")]
	public void CryptoBaseSha512()
	{
		Hkdf.DeriveKey<Sha512Core>(_ikm, _sha512Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-512")]
	public void BclSha512()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA512, _ikm, _sha512Output, _salt, _info);
	}
}

public class HkdfOverlapBenchmark() : HkdfOverlapBenchmarkBase<Sha256Core>(HashAlgorithmName.SHA256);

public class HkdfSha512OverlapBenchmark() : HkdfOverlapBenchmarkBase<Sha512Core>(HashAlgorithmName.SHA512);

[MemoryDiagnoser]
public abstract class HkdfOverlapBenchmarkBase<TCore>(HashAlgorithmName hashAlgorithm) where TCore : unmanaged, IHmacHashCore<TCore>
{
	[Params(65, 8192)]
	public int InfoLength { get; set; }

	[Params(32, 97)]
	public int OutputLength { get; set; }

	private byte[] _prk = [];
	private byte[] _cryptoBaseBuffer = [];
	private byte[] _bclBuffer = [];

	[GlobalSetup]
	public void Setup()
	{
		_prk = RandomNumberGenerator.GetBytes(HashAlgorithm<TCore>.HashLength);
		int bufferLength = Math.Max(InfoLength, OutputLength);
		_cryptoBaseBuffer = new byte[bufferLength];
		_bclBuffer = new byte[bufferLength];
		RandomNumberGenerator.Fill(_cryptoBaseBuffer.AsSpan(0, InfoLength));
		_cryptoBaseBuffer.AsSpan().CopyTo(_bclBuffer);
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Hkdf.Expand<TCore>(_prk, _cryptoBaseBuffer.AsSpan(0, OutputLength), _cryptoBaseBuffer.AsSpan(0, InfoLength));
	}

	[Benchmark]
	public void Bcl()
	{
		HKDF.Expand(hashAlgorithm, _prk, _bclBuffer.AsSpan(0, OutputLength), _bclBuffer.AsSpan(0, InfoLength));
	}
}
