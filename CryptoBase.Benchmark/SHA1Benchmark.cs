using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.SHA1;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class SHA1Benchmark
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
		public void Normal()
		{
			Span<byte> hash = stackalloc byte[SHA1DigestBase.Sha1Length];
			SHA1Utils.Default(_randombytes.Span, hash);
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Span<byte> hash = stackalloc byte[SHA1DigestBase.Sha1Length];
			SHA1Utils.BouncyCastle(_randombytes.Span, hash);
		}
	}
}
