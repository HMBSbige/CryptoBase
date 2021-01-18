using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.MD5;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class MD5Benchmark
	{
		[Params(16 + 6, 16 + 16, 114514)]
		public int ByteLength { get; set; }

		private Memory<byte> _randombytes;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(ByteLength).ToArray();
		}

		private void MD5DigestTest(IHash md5)
		{
			Span<byte> hash = stackalloc byte[md5.Length];
			md5.Compute(_randombytes.Span, hash);
		}

		[Benchmark(Baseline = true)]
		public void Normal()
		{
			MD5DigestTest(new NormalMD5Digest());
		}

		[Benchmark]
		public void BouncyCastle()
		{
			MD5DigestTest(new BcMD5Digest());
		}

		[Benchmark]
		public void SlowMD5()
		{
			MD5DigestTest(new SlowMD5Digest());
		}
	}
}
