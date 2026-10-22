using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using System.Security.Cryptography;
using BouncyCastleDigest = Org.BouncyCastle.Crypto.IDigest;
using BouncyCastleHmac = Org.BouncyCastle.Crypto.Macs.HMac;
using BouncyCastleKeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using BouncyCastleMD5 = Org.BouncyCastle.Crypto.Digests.MD5Digest;
using BouncyCastleSha1 = Org.BouncyCastle.Crypto.Digests.Sha1Digest;
using BouncyCastleSha224 = Org.BouncyCastle.Crypto.Digests.Sha224Digest;
using BouncyCastleSha256 = Org.BouncyCastle.Crypto.Digests.Sha256Digest;
using BouncyCastleSha3 = Org.BouncyCastle.Crypto.Digests.Sha3Digest;
using BouncyCastleSha384 = Org.BouncyCastle.Crypto.Digests.Sha384Digest;
using BouncyCastleSha512 = Org.BouncyCastle.Crypto.Digests.Sha512Digest;
using BouncyCastleSM3 = Org.BouncyCastle.Crypto.Digests.SM3Digest;

namespace CryptoBase.Benchmark.Macs.Hmac;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class HmacBenchmark
{
	private const int MaxInputLength = 1024 * 1024;
	private const int MaxKeyLength = 137;
	private byte[] _input = [];

	private byte[] _key = [];
	private byte[] _mac = [];

	public static IEnumerable<object[]> Block64Arguments()
	{
		return Arguments(64);
	}

	public static IEnumerable<object[]> Block128Arguments()
	{
		return Arguments(128);
	}

	// The HMAC block size of SHA3-256 is its 136-byte rate (FIPS 202, Table 3).
	public static IEnumerable<object[]> Rate136Arguments()
	{
		return Arguments(136);
	}

	public static IEnumerable<object[]> Rate72Arguments()
	{
		return Arguments(72);
	}

	private static IEnumerable<object[]> Arguments(int blockSize)
	{
		yield return [0, blockSize];
		yield return [blockSize, blockSize];
		yield return [1024, blockSize - 1];
		yield return [1024, blockSize];
		yield return [1024, blockSize + 1];
		yield return [8192, blockSize];
		yield return [MaxInputLength, blockSize];
	}

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(MaxKeyLength);
		_input = RandomNumberGenerator.GetBytes(MaxInputLength);
		_mac = new byte[HmacAlgorithm<Sha512Core>.MacLength];
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-MD5")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int MD5Bcl(int inputLength, int keyLength)
	{
		return HMACMD5.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-MD5")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int MD5CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<MD5Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-MD5")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int MD5BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleMD5(), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA1")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha1Bcl(int inputLength, int keyLength)
	{
		return HMACSHA1.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA1")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha1CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha1Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA1")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha1BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha1(), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA224")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha224CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha224Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA224")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha224BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha224(), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA256")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha256Bcl(int inputLength, int keyLength)
	{
		return HMACSHA256.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA256")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha256CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha256Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA256")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha256Platform(int inputLength, int keyLength)
	{
		return PlatformHmacSha256.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA256")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha256BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha256(), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA384")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha384Bcl(int inputLength, int keyLength)
	{
		return HMACSHA384.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA384")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha384CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha384Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA384")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha384BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha384(), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA512")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha512Bcl(int inputLength, int keyLength)
	{
		return HMACSHA512.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA512")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha512CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha512Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA512")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha512BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha512(), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA3-256")]
	[ArgumentsSource(nameof(Rate136Arguments))]
	public int Sha3_256Bcl(int inputLength, int keyLength)
	{
		return HMACSHA3_256.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA3-256")]
	[ArgumentsSource(nameof(Rate136Arguments))]
	public int Sha3_256CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha3_256Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA3-256")]
	[ArgumentsSource(nameof(Rate136Arguments))]
	public int Sha3_256BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha3(256), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA3-512")]
	[ArgumentsSource(nameof(Rate72Arguments))]
	public int Sha3_512Bcl(int inputLength, int keyLength)
	{
		return HMACSHA3_512.HashData(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA3-512")]
	[ArgumentsSource(nameof(Rate72Arguments))]
	public int Sha3_512CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha3_512Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA3-512")]
	[ArgumentsSource(nameof(Rate72Arguments))]
	public int Sha3_512BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSha3(512), inputLength, keyLength);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SM3")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int SM3CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<SM3Core>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SM3")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int SM3BouncyCastle(int inputLength, int keyLength)
	{
		return BouncyCastleCore(new BouncyCastleSM3(), inputLength, keyLength);
	}

	private int BouncyCastleCore(BouncyCastleDigest digest, int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(digest);
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
	}
}
