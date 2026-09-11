using System.Numerics;

namespace CryptoBase.Internal.Extensions;

internal static class ScalarBitOperationsExtensions
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

	extension(ulong value)
	{
		/// <inheritdoc cref="BitOperations.RotateLeft(ulong,int)" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ulong RotateLeft(int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}

		/// <inheritdoc cref="BitOperations.RotateRight(ulong,int)" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ulong RotateRight(int offset)
		{
			return BitOperations.RotateRight(value, offset);
		}
	}
}
