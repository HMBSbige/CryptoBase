using BenchmarkDotNet.Attributes;
using CryptoBase.Digests;
using CryptoBase.Macs.Hmac;
using System;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class HMACBenchmark
	{
		[Params(32, 114514)]
		public int ByteLength { get; set; }

		private byte[] _randombytes = null!;
		private byte[] _randomKey = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(ByteLength).ToArray();
			_randomKey = Utils.RandBytes(64).ToArray();
		}

		[Benchmark]
		public void Managed()
		{
			using var mac = HmacUtils.Create(DigestType.Sha1, _randomKey);
			mac.Update(_randombytes);

			Span<byte> temp = stackalloc byte[mac.Length];
			mac.GetMac(temp);
		}

		[Benchmark(Baseline = true)]
		public void Default()
		{
			using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, _randomKey);
			mac.AppendData(_randombytes);

			Span<byte> temp = stackalloc byte[mac.HashLengthInBytes];
			mac.GetHashAndReset(temp);
		}
	}
}
