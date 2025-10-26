using System.Numerics;

namespace CryptoBase;

public static class Extensions
{
	/// <inheritdoc cref="BitOperations.RotateLeft(uint,int)" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint RotateLeft(this uint value, int offset)
	{
		return BitOperations.RotateLeft(value, offset);
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

			foreach (ref readonly T t in span)
			{
				hash = (hash << 5) + hash ^ t.GetHashCode();
			}

			return hash;
		}
	}
}
