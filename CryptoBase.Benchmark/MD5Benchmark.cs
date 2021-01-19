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

		[Benchmark(Baseline = true)]
		public void Normal()
		{
			Span<byte> hash = stackalloc byte[MD5DigestBase.Md5Len];
			MD5Utils.Default(_randombytes.Span, hash);
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Span<byte> hash = stackalloc byte[MD5DigestBase.Md5Len];
			MD5Utils.BouncyCastle(_randombytes.Span, hash);
		}

		[Benchmark]
		public void SlowMD5()
		{
			Span<byte> hash = stackalloc byte[MD5DigestBase.Md5Len];
			MD5Utils.MayFast(_randombytes.Span, hash);
		}
	}
}
