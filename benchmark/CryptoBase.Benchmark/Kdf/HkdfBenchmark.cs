using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kdf;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Hkdf64Benchmark
{
	[Params(0, 1, 63, 64, 65, 128, 256, 1024, 8192, 1024 * 1024)]
	public int ByteLength { get; set; }

	private byte[] _ikm = [];
	private byte[] _salt = [];
	private byte[] _info = [];
	private byte[] _sha1Prk = [];
	private byte[] _sha1Output = [];
	private byte[] _sha256Prk = [];
	private byte[] _sha256Output = [];

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(ByteLength);
		_salt = RandomNumberGenerator.GetBytes(Sha256HashAlgorithm.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_sha1Prk = new byte[HashAlgorithm<Sha1HashAlgorithm>.HashLength];
		_sha1Output = new byte[2 * HashAlgorithm<Sha1HashAlgorithm>.HashLength + 1];
		_sha256Prk = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		_sha256Output = new byte[2 * HashAlgorithm<Sha256HashAlgorithm>.HashLength + 1];
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-1 Extract")]
	public int BclSha1Extract()
	{
		return HKDF.Extract(HashAlgorithmName.SHA1, _ikm, _salt, _sha1Prk);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-1 Extract")]
	public int CryptoBaseSha1Extract()
	{
		return Hkdf.Extract<Sha1HashAlgorithm>(_ikm, _salt, _sha1Prk);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-1 DeriveKey")]
	public void BclSha1DeriveKey()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA1, _ikm, _sha1Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-1 DeriveKey")]
	public void CryptoBaseSha1DeriveKey()
	{
		Hkdf.DeriveKey<Sha1HashAlgorithm>(_ikm, _sha1Output, _salt, _info);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-256 Extract")]
	public int BclSha256Extract()
	{
		return HKDF.Extract(HashAlgorithmName.SHA256, _ikm, _salt, _sha256Prk);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256 Extract")]
	public int CryptoBaseSha256Extract()
	{
		return Hkdf.Extract<Sha256HashAlgorithm>(_ikm, _salt, _sha256Prk);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256 Extract")]
	public int GenericSha256Extract()
	{
		return Hkdf<HmacAlgorithm<Sha256HashAlgorithm>>.Extract(_ikm, _salt, _sha256Prk);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256 Extract")]
	public int PlatformSha256Extract()
	{
		return Hkdf<PlatformHmacSha256>.Extract(_ikm, _salt, _sha256Prk);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-256 DeriveKey")]
	public void BclSha256DeriveKey()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA256, _ikm, _sha256Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256 DeriveKey")]
	public void CryptoBaseSha256DeriveKey()
	{
		Hkdf.DeriveKey<Sha256HashAlgorithm>(_ikm, _sha256Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256 DeriveKey")]
	public void GenericSha256DeriveKey()
	{
		Hkdf<HmacAlgorithm<Sha256HashAlgorithm>>.DeriveKey(_ikm, _sha256Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256 DeriveKey")]
	public void PlatformSha256DeriveKey()
	{
		Hkdf<PlatformHmacSha256>.DeriveKey(_ikm, _sha256Output, _salt, _info);
	}
}

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Hkdf128Benchmark
{
	[Params(0, 1, 127, 128, 129, 256, 1024, 8192, 1024 * 1024)]
	public int ByteLength { get; set; }

	private byte[] _ikm = [];
	private byte[] _salt = [];
	private byte[] _info = [];
	private byte[] _sha384Prk = [];
	private byte[] _sha384Output = [];
	private byte[] _sha512Prk = [];
	private byte[] _sha512Output = [];

	[GlobalSetup]
	public void Setup()
	{
		_ikm = RandomNumberGenerator.GetBytes(ByteLength);
		_salt = RandomNumberGenerator.GetBytes(Sha512HashAlgorithm.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_sha384Prk = new byte[HashAlgorithm<Sha384HashAlgorithm>.HashLength];
		_sha384Output = new byte[2 * HashAlgorithm<Sha384HashAlgorithm>.HashLength + 1];
		_sha512Prk = new byte[HashAlgorithm<Sha512HashAlgorithm>.HashLength];
		_sha512Output = new byte[2 * HashAlgorithm<Sha512HashAlgorithm>.HashLength + 1];
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-384 Extract")]
	public int BclSha384Extract()
	{
		return HKDF.Extract(HashAlgorithmName.SHA384, _ikm, _salt, _sha384Prk);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-384 Extract")]
	public int CryptoBaseSha384Extract()
	{
		return Hkdf.Extract<Sha384HashAlgorithm>(_ikm, _salt, _sha384Prk);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-384 DeriveKey")]
	public void BclSha384DeriveKey()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA384, _ikm, _sha384Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-384 DeriveKey")]
	public void CryptoBaseSha384DeriveKey()
	{
		Hkdf.DeriveKey<Sha384HashAlgorithm>(_ikm, _sha384Output, _salt, _info);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-512 Extract")]
	public int BclSha512Extract()
	{
		return HKDF.Extract(HashAlgorithmName.SHA512, _ikm, _salt, _sha512Prk);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-512 Extract")]
	public int CryptoBaseSha512Extract()
	{
		return Hkdf.Extract<Sha512HashAlgorithm>(_ikm, _salt, _sha512Prk);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-512 DeriveKey")]
	public void BclSha512DeriveKey()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA512, _ikm, _sha512Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-512 DeriveKey")]
	public void CryptoBaseSha512DeriveKey()
	{
		Hkdf.DeriveKey<Sha512HashAlgorithm>(_ikm, _sha512Output, _salt, _info);
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
		_salt = RandomNumberGenerator.GetBytes(Sha256HashAlgorithm.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_output = new byte[BlockCount * HashAlgorithm<Sha256HashAlgorithm>.HashLength];
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Hkdf.DeriveKey<Sha256HashAlgorithm>(_ikm, _output, _salt, _info);
	}

	[Benchmark]
	public void Bcl()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA256, _ikm, _output, _salt, _info);
	}

	[Benchmark]
	public void Generic()
	{
		Hkdf<HmacAlgorithm<Sha256HashAlgorithm>>.DeriveKey(_ikm, _output, _salt, _info);
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
		_prk = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
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
		return Hkdf.Extract<Sha256HashAlgorithm>(_ikm, _salt, _prk);
	}

	[Benchmark]
	[BenchmarkCategory("Extract")]
	public int GenericExtract()
	{
		return Hkdf<HmacAlgorithm<Sha256HashAlgorithm>>.Extract(_ikm, _salt, _prk);
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
		Hkdf.Expand<Sha256HashAlgorithm>(_prk, _output, _info);
	}

	[Benchmark]
	[BenchmarkCategory("Expand")]
	public void GenericExpand()
	{
		Hkdf<HmacAlgorithm<Sha256HashAlgorithm>>.Expand(_prk, _output, _info);
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
		Hkdf.DeriveKey<Sha256HashAlgorithm>(_ikm, _output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveKey")]
	public void GenericDeriveKey()
	{
		Hkdf<HmacAlgorithm<Sha256HashAlgorithm>>.DeriveKey(_ikm, _output, _salt, _info);
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
		_salt = RandomNumberGenerator.GetBytes(Sha512HashAlgorithm.HmacBlockSize);
		_info = RandomNumberGenerator.GetBytes(80);
		_sha384Output = new byte[BlockCount * HashAlgorithm<Sha384HashAlgorithm>.HashLength];
		_sha512Output = new byte[BlockCount * HashAlgorithm<Sha512HashAlgorithm>.HashLength];
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-384")]
	public void CryptoBaseSha384()
	{
		Hkdf.DeriveKey<Sha384HashAlgorithm>(_ikm, _sha384Output, _salt, _info);
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
		Hkdf.DeriveKey<Sha512HashAlgorithm>(_ikm, _sha512Output, _salt, _info);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-512")]
	public void BclSha512()
	{
		HKDF.DeriveKey(HashAlgorithmName.SHA512, _ikm, _sha512Output, _salt, _info);
	}
}

public class HkdfOverlapBenchmark() : HkdfOverlapBenchmarkBase<Sha256HashAlgorithm>(HashAlgorithmName.SHA256);

public class HkdfSha512OverlapBenchmark() : HkdfOverlapBenchmarkBase<Sha512HashAlgorithm>(HashAlgorithmName.SHA512);

[MemoryDiagnoser]
public abstract class HkdfOverlapBenchmarkBase<THash>(HashAlgorithmName hashAlgorithm) where THash : unmanaged, IHmacHashCore<THash>
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
		_prk = RandomNumberGenerator.GetBytes(HashAlgorithm<THash>.HashLength);
		int bufferLength = Math.Max(InfoLength, OutputLength);
		_cryptoBaseBuffer = new byte[bufferLength];
		_bclBuffer = new byte[bufferLength];
		RandomNumberGenerator.Fill(_cryptoBaseBuffer.AsSpan(0, InfoLength));
		_cryptoBaseBuffer.AsSpan().CopyTo(_bclBuffer);
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Hkdf.Expand<THash>(_prk, _cryptoBaseBuffer.AsSpan(0, OutputLength), _cryptoBaseBuffer.AsSpan(0, InfoLength));
	}

	[Benchmark]
	public void Bcl()
	{
		HKDF.Expand(hashAlgorithm, _prk, _bclBuffer.AsSpan(0, OutputLength), _bclBuffer.AsSpan(0, InfoLength));
	}
}
