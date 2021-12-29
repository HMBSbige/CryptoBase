using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase;

public static class Utils
{
	public static Span<byte> RandBytes(int size)
	{
		Span<byte> bytes = new byte[size];
		RandomNumberGenerator.Fill(bytes);
		return bytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Swap<T>(ref T a, ref T b)
	{
		var t = a;
		a = b;
		b = t;
	}
}
