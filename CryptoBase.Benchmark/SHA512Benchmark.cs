using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SHA512;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class SHA512Benchmark
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
		public void Default()
		{
			Span<byte> hash = stackalloc byte[HashConstants.Sha512Length];
			SHA512Utils.Default(_randombytes.Span, hash);
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Span<byte> hash = stackalloc byte[HashConstants.Sha512Length];
			BcDigestsUtils.SHA512(_randombytes.Span, hash);
		}
	}
}
