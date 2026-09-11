using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha224;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using System.Security.Cryptography;
using BouncyCastleHmac = Org.BouncyCastle.Crypto.Macs.HMac;
using BouncyCastleKeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using BouncyCastleMD5 = Org.BouncyCastle.Crypto.Digests.MD5Digest;
using BouncyCastleSha1 = Org.BouncyCastle.Crypto.Digests.Sha1Digest;
using BouncyCastleSha224 = Org.BouncyCastle.Crypto.Digests.Sha224Digest;
using BouncyCastleSha256 = Org.BouncyCastle.Crypto.Digests.Sha256Digest;
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
	private const int MaxKeyLength = 129;
	private byte[] _input = [];

	private byte[] _key = [];
	private byte[] _mac = [];

	public static IEnumerable<object[]> Block64Arguments()
	{
		yield return [0, 64];
		yield return [64, 64];
		yield return [1024, 63];
		yield return [1024, 64];
		yield return [1024, 65];
		yield return [8192, 64];
		yield return [MaxInputLength, 64];
	}

	public static IEnumerable<object[]> Block128Arguments()
	{
		yield return [0, 128];
		yield return [128, 128];
		yield return [1024, 127];
		yield return [1024, 128];
		yield return [1024, 129];
		yield return [8192, 128];
		yield return [MaxInputLength, 128];
	}

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(MaxKeyLength);
		_input = RandomNumberGenerator.GetBytes(MaxInputLength);
		_mac = new byte[HmacAlgorithm<Sha512HashAlgorithm>.MacLengthInBytes];
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
		return HmacAlgorithm<MD5HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-MD5")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int MD5BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleMD5());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
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
		return HmacAlgorithm<Sha1HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA1")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha1BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleSha1());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SHA224")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha224CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<Sha224HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA224")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha224BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleSha224());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
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
		return HmacAlgorithm<Sha256HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA256")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int Sha256BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleSha256());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
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
		return HmacAlgorithm<Sha384HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA384")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha384BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleSha384());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
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
		return HmacAlgorithm<Sha512HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SHA512")]
	[ArgumentsSource(nameof(Block128Arguments))]
	public int Sha512BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleSha512());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("HMAC-SM3")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int SM3CryptoBase(int inputLength, int keyLength)
	{
		return HmacAlgorithm<SM3HashAlgorithm>.Mac(_key.AsSpan(0, keyLength), _input.AsSpan(0, inputLength), _mac);
	}

	[Benchmark]
	[BenchmarkCategory("HMAC-SM3")]
	[ArgumentsSource(nameof(Block64Arguments))]
	public int SM3BouncyCastle(int inputLength, int keyLength)
	{
		BouncyCastleHmac hmac = new(new BouncyCastleSM3());
		hmac.Init(new BouncyCastleKeyParameter(_key.AsSpan(0, keyLength)));
		hmac.BlockUpdate(_input.AsSpan(0, inputLength));
		return hmac.DoFinal(_mac);
	}
}
