using CryptoBase.Abstractions;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Macs.Poly1305;

public static class Poly1305Utils
{
	public const int KeySize = 32;
	public const int BlockSize = 16;
	public const int TagSize = 16;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IMac Create(ReadOnlySpan<byte> key)
	{
		if (Sse2.IsSupported)
		{
			return new Poly1305X86(key);
		}

		return new Poly1305SF(key);
	}
}
