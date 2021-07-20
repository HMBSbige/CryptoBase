using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA512
{
	public static class SHA512Utils
	{
		private static readonly ThreadLocal<IHash> Normal = new(() => new DefaultSHA512Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.UpdateFinal(origin, destination);
		}
	}
}
