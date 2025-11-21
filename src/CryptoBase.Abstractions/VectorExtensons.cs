namespace CryptoBase.Abstractions;

public static class VectorExtensons
{
	extension<TLeft>(ref Vector512X16<TLeft> left)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add<TRight>(in Vector512X16<TRight> right)
		{
			left.V0 += right.V0.As<TRight, TLeft>();
			left.V1 += right.V1.As<TRight, TLeft>();
			left.V2 += right.V2.As<TRight, TLeft>();
			left.V3 += right.V3.As<TRight, TLeft>();
			left.V4 += right.V4.As<TRight, TLeft>();
			left.V5 += right.V5.As<TRight, TLeft>();
			left.V6 += right.V6.As<TRight, TLeft>();
			left.V7 += right.V7.As<TRight, TLeft>();
			left.V8 += right.V8.As<TRight, TLeft>();
			left.V9 += right.V9.As<TRight, TLeft>();
			left.V10 += right.V10.As<TRight, TLeft>();
			left.V11 += right.V11.As<TRight, TLeft>();
			left.V12 += right.V12.As<TRight, TLeft>();
			left.V13 += right.V13.As<TRight, TLeft>();
			left.V14 += right.V14.As<TRight, TLeft>();
			left.V15 += right.V15.As<TRight, TLeft>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Xor<TRight>(in Vector512X16<TRight> right)
		{
			left.V0 ^= right.V0.As<TRight, TLeft>();
			left.V1 ^= right.V1.As<TRight, TLeft>();
			left.V2 ^= right.V2.As<TRight, TLeft>();
			left.V3 ^= right.V3.As<TRight, TLeft>();
			left.V4 ^= right.V4.As<TRight, TLeft>();
			left.V5 ^= right.V5.As<TRight, TLeft>();
			left.V6 ^= right.V6.As<TRight, TLeft>();
			left.V7 ^= right.V7.As<TRight, TLeft>();
			left.V8 ^= right.V8.As<TRight, TLeft>();
			left.V9 ^= right.V9.As<TRight, TLeft>();
			left.V10 ^= right.V10.As<TRight, TLeft>();
			left.V11 ^= right.V11.As<TRight, TLeft>();
			left.V12 ^= right.V12.As<TRight, TLeft>();
			left.V13 ^= right.V13.As<TRight, TLeft>();
			left.V14 ^= right.V14.As<TRight, TLeft>();
			left.V15 ^= right.V15.As<TRight, TLeft>();
		}
	}

	extension<TLeft>(ref Vector256X16<TLeft> left)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add<TRight>(in Vector256X16<TRight> right)
		{
			left.V0 += right.V0.As<TRight, TLeft>();
			left.V1 += right.V1.As<TRight, TLeft>();
			left.V2 += right.V2.As<TRight, TLeft>();
			left.V3 += right.V3.As<TRight, TLeft>();
			left.V4 += right.V4.As<TRight, TLeft>();
			left.V5 += right.V5.As<TRight, TLeft>();
			left.V6 += right.V6.As<TRight, TLeft>();
			left.V7 += right.V7.As<TRight, TLeft>();
			left.V8 += right.V8.As<TRight, TLeft>();
			left.V9 += right.V9.As<TRight, TLeft>();
			left.V10 += right.V10.As<TRight, TLeft>();
			left.V11 += right.V11.As<TRight, TLeft>();
			left.V12 += right.V12.As<TRight, TLeft>();
			left.V13 += right.V13.As<TRight, TLeft>();
			left.V14 += right.V14.As<TRight, TLeft>();
			left.V15 += right.V15.As<TRight, TLeft>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Xor<TRight>(in Vector256X16<TRight> right)
		{
			left.V0 ^= right.V0.As<TRight, TLeft>();
			left.V1 ^= right.V1.As<TRight, TLeft>();
			left.V2 ^= right.V2.As<TRight, TLeft>();
			left.V3 ^= right.V3.As<TRight, TLeft>();
			left.V4 ^= right.V4.As<TRight, TLeft>();
			left.V5 ^= right.V5.As<TRight, TLeft>();
			left.V6 ^= right.V6.As<TRight, TLeft>();
			left.V7 ^= right.V7.As<TRight, TLeft>();
			left.V8 ^= right.V8.As<TRight, TLeft>();
			left.V9 ^= right.V9.As<TRight, TLeft>();
			left.V10 ^= right.V10.As<TRight, TLeft>();
			left.V11 ^= right.V11.As<TRight, TLeft>();
			left.V12 ^= right.V12.As<TRight, TLeft>();
			left.V13 ^= right.V13.As<TRight, TLeft>();
			left.V14 ^= right.V14.As<TRight, TLeft>();
			left.V15 ^= right.V15.As<TRight, TLeft>();
		}
	}
}
