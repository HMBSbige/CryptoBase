using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA384
{
	public static class SHA384Utils
	{
		private static readonly ThreadLocal<IHash> Normal = new(() => new DefaultSHA384Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.UpdateFinal(origin, destination);
		}
	}
}
