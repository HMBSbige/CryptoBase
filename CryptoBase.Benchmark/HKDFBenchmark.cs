using BenchmarkDotNet.Attributes;
using CryptoBase.Digests;
using CryptoBase.KDF;
using System;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class HKDFBenchmark
	{
		[Params(1)]
		public int Max { get; set; }

		private byte[] _ikm = null!;
		private byte[] _salt = null!;
		private byte[] _info = null!;

		[GlobalSetup]
		public void Setup()
		{
			_ikm = Utils.RandBytes(80).ToArray();
			_salt = Utils.RandBytes(80).ToArray();
			_info = Utils.RandBytes(80).ToArray();
		}

		[Benchmark]
		public void Default()
		{
			Span<byte> output = stackalloc byte[82];
			for (var i = 0; i < Max; ++i)
			{
				Hkdf.DeriveKey(DigestType.Sha256, _ikm, output, _salt, _info);
			}
		}

		[Benchmark(Baseline = true)]
		public void NET()
		{
			Span<byte> output = stackalloc byte[82];
			for (var i = 0; i < Max; ++i)
			{
				HKDF.DeriveKey(HashAlgorithmName.SHA256, _ikm, output, _salt, _info);
			}
		}
	}
}
