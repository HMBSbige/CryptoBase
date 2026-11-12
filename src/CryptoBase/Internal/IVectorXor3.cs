namespace CryptoBase.Internal;

// The three-way XORs of an ARM64 kernel, which runs as one instantiation with VectorXor3.Eor3 and another with VectorXor3.Plain and picks between them where it starts.
internal interface IVectorXor3
{
	static abstract Vector128<T> Xor<T>(Vector128<T> first, Vector128<T> second, Vector128<T> third);
}

internal static class VectorXor3
{
	internal readonly struct Plain : IVectorXor3
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<T> Xor<T>(Vector128<T> first, Vector128<T> second, Vector128<T> third)
		{
			return first ^ second ^ third;
		}
	}

#if NET11_0_OR_GREATER
	internal readonly struct Eor3 : IVectorXor3
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<T> Xor<T>(Vector128<T> first, Vector128<T> second, Vector128<T> third)
		{
			return Sha3.Xor(first.AsByte(), second.AsByte(), third.AsByte()).As<byte, T>();
		}
	}
#endif
}
