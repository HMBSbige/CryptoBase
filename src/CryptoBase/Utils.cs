namespace CryptoBase;

public static class Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Swap<T>(ref T a, ref T b)
	{
		// faster than (a, b) = (b, a);
		T t = a;
		a = b;
		b = t;
	}
}
