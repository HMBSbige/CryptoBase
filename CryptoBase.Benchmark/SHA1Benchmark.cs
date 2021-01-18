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

		private void SHADigestTest(IHash sha1)
		{
			Span<byte> hash = stackalloc byte[sha1.Length];
			sha1.ComputeHash(_randombytes.Span, hash);
		}

		[Benchmark(Baseline = true)]
		public void Normal()
		{
			SHADigestTest(new NormalSHA1Digest());
		}

		[Benchmark]
		public void BouncyCastle()
		{
			SHADigestTest(new NormalSHA1Digest());
		}
	}
}
