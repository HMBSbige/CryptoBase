using CryptoBase.Abstractions;

namespace CryptoBase.Macs.GHash;

public static class GHashUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IMac Create(ReadOnlySpan<byte> key)
	{
		if (Sse2.IsSupported && Ssse3.IsSupported && Pclmulqdq.IsSupported)
		{
			return new GHashX86(key);
		}

		return new GHashSF(key);
	}
}
