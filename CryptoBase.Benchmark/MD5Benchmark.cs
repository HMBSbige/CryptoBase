using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
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

		[Benchmark]
		public void Default()
		{
			Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
			MD5Utils.Default(_randombytes.Span, hash);
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
			BcDigestsUtils.MD5(_randombytes.Span, hash);
		}

		[Benchmark]
		public void MayFast()
		{
			Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
			MD5Utils.MayFast(_randombytes.Span, hash);
		}

		[Benchmark(Baseline = true)]
		public void Fast440()
		{
			if (_randombytes.Length > 55)
			{
				return;
			}
			Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
			MD5Utils.Fast440(_randombytes.Span, hash);
		}
	}
}
