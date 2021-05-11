using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Diagnostics;

namespace CryptoBase.SpeedTest
{
	public static class CryptoTest
	{
		public static ReadOnlySpan<byte> Key => new byte[]
		{
			0, 1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23,
			24, 25, 26, 27, 28, 29, 30, 31
		};

		public static ReadOnlySpan<byte> IV => new byte[]
		{
			0, 1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23,
			24, 25, 26, 27, 28, 29, 30, 31
		};

		private const int Step = 4 * 1024; // 4 KB
		private const int Duration = 3 * 1000; // 3s

		public static void Test(IStreamCrypto crypto)
		{
			ReadOnlySpan<byte> i = new byte[Step];
			Span<byte> o = new byte[Step];

			var sw = Stopwatch.StartNew();
			var length = 0ul;

			do
			{
				crypto.Update(i, o);
				++length;
			} while (sw.ElapsedMilliseconds < Duration);

			sw.Stop();
			crypto.Dispose();

			var result = length * Step / sw.Elapsed.TotalSeconds / 1024.0 / 1024.0;
			Console.WriteLine($@"{result:F2} MB/s");
		}

		public static void Test(IAEADCrypto crypto, int nonceLength = 12)
		{
			ReadOnlySpan<byte> i = new byte[Step];
			Span<byte> o = new byte[Step];
			ReadOnlySpan<byte> nonce = IV.Slice(0, nonceLength);
			Span<byte> tag = stackalloc byte[16];

			var sw = Stopwatch.StartNew();
			var length = 0ul;

			do
			{
				crypto.Encrypt(nonce, i, o, tag);
				++length;
			} while (sw.ElapsedMilliseconds < Duration);

			sw.Stop();
			crypto.Dispose();

			var result = length * Step / sw.Elapsed.TotalSeconds / 1024.0 / 1024.0;
			Console.WriteLine($@"{result:F2} MB/s");
		}
	}
}
