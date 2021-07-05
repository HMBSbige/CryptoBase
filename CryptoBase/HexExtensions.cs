using System;
using System.Runtime.CompilerServices;

namespace CryptoBase
{
	public static class HexExtensions
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static string ToHex(this Span<byte> bytes)
		{
			return Convert.ToHexString(bytes);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static string ToHex(this ReadOnlySpan<byte> bytes)
		{
			return Convert.ToHexString(bytes);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static byte[] FromHex(this string hex)
		{
			hex = hex.Replace(@"0x", string.Empty).Replace(@"-", string.Empty);
			return Convert.FromHexString(hex);
		}
	}
}
