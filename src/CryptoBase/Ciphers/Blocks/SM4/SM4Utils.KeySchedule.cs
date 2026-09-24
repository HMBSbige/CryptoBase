using AesArm = System.Runtime.Intrinsics.Arm.Aes;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal static partial class SM4Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void InitRoundKeysNeon(uint k0, uint k1, uint k2, uint k3, ref uint rk)
	{
		byte* s = (byte*)Unsafe.AsPointer(ref S.GetReference());
		(Vector128<byte> s0, Vector128<byte> s1, Vector128<byte> s2, Vector128<byte> s3) = AdvSimd.Arm64.Load4xVector128(s);
		(Vector128<byte> s4, Vector128<byte> s5, Vector128<byte> s6, Vector128<byte> s7) = AdvSimd.Arm64.Load4xVector128(s + 64);
		(Vector128<byte> s8, Vector128<byte> s9, Vector128<byte> s10, Vector128<byte> s11) = AdvSimd.Arm64.Load4xVector128(s + 128);
		(Vector128<byte> s12, Vector128<byte> s13, Vector128<byte> s14, Vector128<byte> s15) = AdvSimd.Arm64.Load4xVector128(s + 192);
		Vector128<byte> tableSize = Vector128.Create((byte)64);
		Vector128<uint> x0 = Vector128.Create(k0);
		Vector128<uint> x1 = Vector128.Create(k1);
		Vector128<uint> x2 = Vector128.Create(k2);
		Vector128<uint> x3 = Vector128.Create(k3);
		ref uint ck = ref CK.GetReference();

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> index = (x1 ^ x2 ^ x3 ^ Vector128.Create(Unsafe.Add(ref ck, i))).AsByte();
			Vector128<byte> value = AdvSimd.Arm64.VectorTableLookup((s0, s1, s2, s3), index);
			index -= tableSize;
			value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s4, s5, s6, s7), index);
			index -= tableSize;
			value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s8, s9, s10, s11), index);
			index -= tableSize;
			value = AdvSimd.Arm64.VectorTableLookupExtension(value, (s12, s13, s14, s15), index);

			Vector128<uint> t = value.AsUInt32();
			Vector128<uint> next = x0 ^ t ^ t.RotateLeftUInt32(13) ^ t.RotateLeftUInt32(23);
			Unsafe.Add(ref rk, i) = next.ToScalar();
			x0 = x1;
			x1 = x2;
			x2 = x3;
			x3 = next;
		}
	}

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
