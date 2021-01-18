using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
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

		private void SM3DigestTest(IHash sm3)
		{
			Span<byte> hash = stackalloc byte[sm3.Length];
			sm3.ComputeHash(_randombytes.Span, hash);
		}

		[Benchmark]
		public void SlowSM3()
		{
			SM3DigestTest(new SlowSM3Digest());
		}

		[Benchmark(Baseline = true)]
		public void BouncyCastle()
		{
			SM3DigestTest(new BcSM3Digest());
		}
	}
}
