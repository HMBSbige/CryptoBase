using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5;

[Obsolete(@"Use DigestUtils.Create(DigestType.Md5)")]
public static class MD5Utils
{
	private static readonly ThreadLocal<IHash> Normal = new(() => new DefaultMD5Digest());
	private static readonly ThreadLocal<IHash> Slow = new(() => new MD5Digest());
	private static readonly ThreadLocal<IHash> Fast = new(() => new Fast440MD5Digest());

	public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Normal.Value!.UpdateFinal(origin, destination);
	}

	public static void MayFast(in ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Slow.Value!.UpdateFinal(origin, destination);
	}

	public static void Fast440(in ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Fast.Value!.UpdateFinal(origin, destination);
	}
}
