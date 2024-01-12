using System.Numerics;

namespace CryptoBase;

public static class Extensions
{
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
	public static void FixedTimeIncrement(this Span<byte> nonce)
	{
		int c = 1;
		for (int i = 0; i < nonce.Length; ++i)
		{
			c += nonce[i];
			nonce[i] = (byte)c;
			c >>= 8;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
	public static void FixedTimeIncrementBigEndian(this Span<byte> nonce)
	{
		int c = 1;
		for (int i = nonce.Length - 1; i >= 0; --i)
		{
			c += nonce[i];
			nonce[i] = (byte)c;
			c >>= 8;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint RotateLeft(this uint value, int offset)
	{
		return BitOperations.RotateLeft(value, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetClassicHashCode(this string str)
	{
		unchecked
		{
			int hash1 = (5381 << 16) + 5381;
			int hash2 = hash1;

			for (int i = 0; i < str.Length; i += 2)
			{
				hash1 = ((hash1 << 5) + hash1) ^ str[i];
				if (i == str.Length - 1)
				{
					break;
				}

				hash2 = ((hash2 << 5) + hash2) ^ str[i + 1];
			}

			return hash1 + hash2 * 1566083941;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetDeterministicHashCode(this string str)
	{
		return str.AsSpan().GetDeterministicHashCode();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetDeterministicHashCode<T>(this ReadOnlySpan<T> span) where T : notnull
	{
		unchecked
		{
			int hash = 5381;

			foreach (T t in span)
			{
				hash = ((hash << 5) + hash) ^ t.GetHashCode();
			}

			return hash;
		}
	}
}
