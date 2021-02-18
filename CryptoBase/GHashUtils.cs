using CryptoBase.Macs.GHash;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class GHashUtils
	{
		public static bool IsSupportX86 => Sse2.IsSupported && Ssse3.IsSupported && Pclmulqdq.IsSupported;

		public static GHash Create(byte[] key)
		{
			if (IsSupportX86)
			{
				return new GHashX86(key);
			}

			return new GHashSF(key);
		}
	}
}
