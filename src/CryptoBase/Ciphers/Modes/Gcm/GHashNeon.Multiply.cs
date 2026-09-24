namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashNeon
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> CarrylessMultiply64(Vector64<byte> a, Vector64<byte> b)
	{
		Vector128<ulong> cross1 = (AdvSimd.PolynomialMultiplyWideningLower(AdvSimd.ExtractVector64(a, a, 1), b) ^ AdvSimd.PolynomialMultiplyWideningLower(a, AdvSimd.ExtractVector64(b, b, 1))).AsUInt64();
		Vector128<ulong> cross2 = (AdvSimd.PolynomialMultiplyWideningLower(AdvSimd.ExtractVector64(a, a, 2), b) ^ AdvSimd.PolynomialMultiplyWideningLower(a, AdvSimd.ExtractVector64(b, b, 2))).AsUInt64();
		Vector128<ulong> cross3 = (AdvSimd.PolynomialMultiplyWideningLower(AdvSimd.ExtractVector64(a, a, 3), b) ^ AdvSimd.PolynomialMultiplyWideningLower(a, AdvSimd.ExtractVector64(b, b, 3))).AsUInt64();
		Vector128<ulong> cross4 = AdvSimd.PolynomialMultiplyWideningLower(a, AdvSimd.ExtractVector64(b, b, 4)).AsUInt64();

		Vector128<ulong> low12 = AdvSimd.Arm64.ZipLow(cross1, cross2);
		Vector128<ulong> high12 = AdvSimd.Arm64.ZipHigh(cross1, cross2);
		Vector128<ulong> low34 = AdvSimd.Arm64.ZipLow(cross3, cross4);
		Vector128<ulong> high34 = AdvSimd.Arm64.ZipHigh(cross3, cross4);

		low12 ^= high12;
		low34 ^= high34;
		high12 &= Vector128.Create(0x0000ffffffffffffUL, 0x00000000ffffffffUL);
		high34 &= Vector128.Create(0x000000000000ffffUL, 0UL);
		low12 ^= high12;
		low34 ^= high34;
		Vector128<byte> term1 = AdvSimd.Arm64.ZipLow(low12, high12).AsByte();
		Vector128<byte> term2 = AdvSimd.Arm64.ZipHigh(low12, high12).AsByte();
		Vector128<byte> term3 = AdvSimd.Arm64.ZipLow(low34, high34).AsByte();
		Vector128<byte> term4 = AdvSimd.Arm64.ZipHigh(low34, high34).AsByte();

		return
		(
			AdvSimd.PolynomialMultiplyWideningLower(a, b).AsByte()
			^ AdvSimd.ExtractVector128(term1, term1, 15)
			^ AdvSimd.ExtractVector128(term2, term2, 14)
			^ AdvSimd.ExtractVector128(term3, term3, 13)
			^ AdvSimd.ExtractVector128(term4, term4, 12)
		).AsUInt64();
	}
}
