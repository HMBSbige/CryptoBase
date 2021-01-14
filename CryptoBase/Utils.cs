using System;
using System.Security.Cryptography;

namespace CryptoBase
{
	public static class Utils
	{
		public static void RandBytes(Span<byte> buf)
		{
			using var rngServiceProvider = new RNGCryptoServiceProvider();
			rngServiceProvider.GetBytes(buf);
		}

		public static Span<byte> RandBytes(int size)
		{
			Span<byte> bytes = new byte[size];
			RandBytes(bytes);
			return bytes;
		}
	}
}
