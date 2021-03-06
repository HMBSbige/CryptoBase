using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SM3
{
	public static class SM3Utils
	{
		private static readonly ThreadLocal<IHash> Slow = new(() => new SM3Digest());

		public static void MayFast(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Slow.Value!.UpdateFinal(origin, destination);
		}
	}
}
