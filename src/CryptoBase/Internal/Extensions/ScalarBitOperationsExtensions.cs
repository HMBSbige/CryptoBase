using System.Numerics;

namespace CryptoBase.Internal.Extensions;

internal static class ScalarBitOperationsExtensions
{
	extension(uint value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public uint RotateLeft(int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public uint RotateRight(int offset)
		{
			return BitOperations.RotateRight(value, offset);
		}
	}

	extension(ulong value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ulong RotateLeft(int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ulong RotateRight(int offset)
		{
			return BitOperations.RotateRight(value, offset);
		}
	}
}
