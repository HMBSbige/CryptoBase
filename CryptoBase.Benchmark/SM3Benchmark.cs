using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests;
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

		[Benchmark]
		public void BouncyCastle()
		{
			Span<byte> hash = stackalloc byte[HashConstants.SM3Length];
			using var sm3 = new BcSM3Digest();
			sm3.UpdateFinal(_randombytes.Span, hash);
		}

		[Benchmark(Baseline = true)]
		public void MayFast()
		{
			Span<byte> hash = stackalloc byte[HashConstants.SM3Length];
			using var sm3 = DigestUtils.Create(DigestType.Sm3);
			sm3.UpdateFinal(_randombytes.Span, hash);
		}
	}
}
