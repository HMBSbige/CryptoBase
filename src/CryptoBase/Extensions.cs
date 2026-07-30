using System.Numerics;

namespace CryptoBase;

/// <summary>
/// Provides low-level extension methods used by cryptographic implementations.
/// </summary>
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

		/// <inheritdoc cref="BitOperations.RotateRight(uint,int)" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public uint RotateRight(int offset)
		{
			return BitOperations.RotateRight(value, offset);
		}
	}

	extension<T>(ReadOnlySpan<T> span) where T : notnull
	{
		/// <summary>
		/// Computes a hash code from the span elements in order.
		/// </summary>
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
