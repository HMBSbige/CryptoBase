using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SM3;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class SM3Benchmark
	{
		[Params(32, 114514)]
		public int ByteLength { get; set; }

		private Memory<byte> _randombytes;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(ByteLength).ToArray();
		}

		[Benchmark(Baseline = true)]
		public void BouncyCastle()
		{
			Span<byte> hash = stackalloc byte[SM3DigestBase.SM3Length];
			BcDigestsUtils.SM3(_randombytes.Span, hash);
		}

		[Benchmark]
		public void Slow()
		{
			Span<byte> hash = stackalloc byte[SM3DigestBase.SM3Length];
			SM3Utils.MayFast(_randombytes.Span, hash);
		}
	}
}
