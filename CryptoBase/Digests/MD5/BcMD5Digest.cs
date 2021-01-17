using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Buffers;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public class BcMD5Digest : MD5DigestBase
	{
		private static readonly ThreadLocal<MD5Digest> Hasher = new(() => new MD5Digest());

		public override Span<byte> Compute(in ReadOnlySpan<byte> origin)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(origin.Length);
			var outBuffer = new byte[Md5Len];
			try
			{
				origin.CopyTo(buffer);

				Hasher.Value!.Reset();
				Hasher.Value!.BlockUpdate(buffer, 0, origin.Length);
				Hasher.Value!.DoFinal(outBuffer, 0);

				return outBuffer;
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}
	}
}
