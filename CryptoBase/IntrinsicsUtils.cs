using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class IntrinsicsUtils
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint AndNot(uint left, uint right)
		{
			if (Bmi1.IsSupported)
			{
				return Bmi1.AndNot(left, right);
			}
			return ~left & right;
		}
	}
}
