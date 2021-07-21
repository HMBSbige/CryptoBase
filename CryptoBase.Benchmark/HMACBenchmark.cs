using BenchmarkDotNet.Attributes;
using CryptoBase.Digests;
using CryptoBase.Macs.Hmac;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class HMACBenchmark
	{
		[Params(32)]
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
		public void HMAC()
		{
			using var mac = HmacUtils.Create(DigestType.Sha1, _randomKey);
			mac.Update(_randombytes);

			Span<byte> temp = stackalloc byte[mac.Length];
			mac.GetMac(temp);
		}

		[Benchmark(Baseline = true)]
		public void Default()
		{
			using var mac = System.Security.Cryptography.HMAC.Create(@"HMACSHA1")!;
			mac.Key = _randomKey;
			Span<byte> temp = stackalloc byte[mac.HashSize >> 3];
			mac.TryComputeHash(_randombytes, temp, out _);
		}
	}
}
