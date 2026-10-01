namespace CryptoBase.Internal.Extensions;

internal static class VectorCreationExtensions
{
	extension(Vector64)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector64<uint> CreateUInt32(uint first, uint second)
		{
			// Broadcast first to break ARM64 INS false dependencies on the old register value.
			return AdvSimd.Arm64.IsSupported
				? Vector64.Create(first).WithElement(1, second)
				: Vector64.Create(first, second);
		}
	}

	extension(Vector128)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<uint> CreateUInt32(uint first, uint second, uint third, uint fourth)
		{
			// Broadcast first to break ARM64 INS false dependencies on the old register value.
			return AdvSimd.Arm64.IsSupported
				? Vector128.Create(first).WithElement(1, second).WithElement(2, third).WithElement(3, fourth)
				: Vector128.Create(first, second, third, fourth);
		}

		// Creates [a, _, b, _].
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<uint> CreateUInt32EvenLanes(uint a, uint b)
		{
			if (Sse2.IsSupported)
			{
				Vector128<uint> t1 = Vector128.CreateScalarUnsafe(a);
				Vector128<uint> t2 = Vector128.CreateScalarUnsafe(b);

				return Sse2.UnpackLow(t1.AsUInt64(), t2.AsUInt64()).AsUInt32();
			}

			return Vector128.Create(a, 0, b, 0);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<ulong> CreateUInt64(ulong low, ulong high)
		{
			// Broadcast first to break ARM64 INS false dependencies on the old register value.
			return AdvSimd.Arm64.IsSupported
				? Vector128.Create(low).WithElement(1, high)
				: Vector128.Create(low, high);
		}
	}

	extension(Vector256)
	{
		// Creates [a, 0, b, 0, c, 0, d, 0].
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector256<uint> CreateUInt32EvenLanes(uint a, uint b, uint c, uint d)
		{
			return Vector256.Create(Vector128.CreateScalar(a).WithElement(2, b), Vector128.CreateScalar(c).WithElement(2, d));
		}
	}
}
