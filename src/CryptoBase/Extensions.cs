using System.Numerics;

namespace CryptoBase;

public static class Extensions
{
	extension(uint value)
	{
		/// <inheritdoc cref="BitOperations.RotateLeft(uint,int)" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public uint RotateLeft(int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}
	}

	extension(string str)
	{
		/// <inheritdoc cref="GetDeterministicHashCode(string)" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public int GetDeterministicHashCode()
		{
			return str.AsSpan().GetDeterministicHashCode();
		}
	}

	extension<T>(ReadOnlySpan<T> span) where T : notnull
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public int GetDeterministicHashCode()
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
}
