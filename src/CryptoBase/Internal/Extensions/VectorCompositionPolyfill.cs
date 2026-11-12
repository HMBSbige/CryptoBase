#if !NET11_0_OR_GREATER
namespace CryptoBase.Internal.Extensions;

internal static class VectorCompositionPolyfill
{
	extension(Vector128)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<sbyte> ZipLower(Vector128<sbyte> left, Vector128<sbyte> right)
		{
			return Sse2.IsSupported ? Sse2.UnpackLow(left, right) : AdvSimd.Arm64.ZipLow(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<sbyte> ZipUpper(Vector128<sbyte> left, Vector128<sbyte> right)
		{
			return Sse2.IsSupported ? Sse2.UnpackHigh(left, right) : AdvSimd.Arm64.ZipHigh(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<uint> ZipLower(Vector128<uint> left, Vector128<uint> right)
		{
			return Sse2.IsSupported ? Sse2.UnpackLow(left, right) : AdvSimd.Arm64.ZipLow(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<uint> ZipUpper(Vector128<uint> left, Vector128<uint> right)
		{
			return Sse2.IsSupported ? Sse2.UnpackHigh(left, right) : AdvSimd.Arm64.ZipHigh(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<ulong> ZipLower(Vector128<ulong> left, Vector128<ulong> right)
		{
			return Sse2.IsSupported ? Sse2.UnpackLow(left, right) : AdvSimd.Arm64.ZipLow(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<ulong> ZipUpper(Vector128<ulong> left, Vector128<ulong> right)
		{
			return Sse2.IsSupported ? Sse2.UnpackHigh(left, right) : AdvSimd.Arm64.ZipHigh(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<uint> UnzipEven(Vector128<uint> left, Vector128<uint> right)
		{
			return Sse.IsSupported ? Sse.Shuffle(left.AsSingle(), right.AsSingle(), 0b10_00_10_00).AsUInt32() : AdvSimd.Arm64.UnzipEven(left, right);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<uint> UnzipOdd(Vector128<uint> left, Vector128<uint> right)
		{
			return Sse.IsSupported ? Sse.Shuffle(left.AsSingle(), right.AsSingle(), 0b11_01_11_01).AsUInt32() : AdvSimd.Arm64.UnzipOdd(left, right);
		}
	}

	extension(Vector256)
	{
		// The .NET 10 JIT copies right before taking its lower half while right is still live, so call ConcatUpper first when both halves are needed.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector256<T> ConcatLowerLower<T>(Vector256<T> left, Vector256<T> right)
		{
			return left.WithUpper(right.GetLower());
		}
	}
}
#endif
