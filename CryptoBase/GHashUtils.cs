using CryptoBase.Abstractions;
using CryptoBase.Macs.GHash;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class GHashUtils
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IMac Create(ReadOnlySpan<byte> key)
		{
			if (Sse2.IsSupported && Ssse3.IsSupported && Pclmulqdq.IsSupported)
			{
				return new GHashX86(key);
			}

			return new GHashSF(key);
		}
	}
}
