using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA256
{
	public static class SHA256Utils
	{
		private static readonly ThreadLocal<IHash> Normal = new(() => new DefaultSHA256Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.UpdateFinal(origin, destination);
		}
	}
}
