namespace CryptoBase.DataFormatExtensions;

internal enum Base32SimdPath
{
	Auto,
	Scalar,
	Ssse3,
	Avx2,
	Avx512Bw,
	Avx512Vbmi,
	Avx512VbmiVl256,
	Avx512VbmiVl128,
	AdvSimd,
}
