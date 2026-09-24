using AesArm = System.Runtime.Intrinsics.Arm.Aes;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal static partial class SM4Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint SubByteKey(uint x)
	{
		if (AesArm.IsSupported && AdvSimd.Arm64.IsSupported)
		{
			LoadConstantsArmAes(out Vector128<byte> preLo, out Vector128<byte> preHi, out Vector128<byte> postLo, out Vector128<byte> postHi, out Vector128<byte> inverseShiftRows, out Vector128<byte> mask);
			return SubByteArmAes(Vector128.CreateScalar(x), preLo, preHi, postLo, postHi, inverseShiftRows, mask).ToScalar();
		}

		if (AesX86.IsSupported && Ssse3.IsSupported)
		{
			Vector128<byte> y = Vector128.CreateScalar(x).AsByte();
			y.PreTransform();
			y = AesX86.EncryptLast(y, Vector128.Create((byte)0x0F));
			y.PostTransform();
			y = Ssse3.Shuffle(y, Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3));
			return y.AsUInt32().ToScalar();
		}

		return SubByte(x);
	}
}
