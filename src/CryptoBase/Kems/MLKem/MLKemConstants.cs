namespace CryptoBase.Kems.MLKem;

// Arithmetic modulo q = 3329 in Montgomery form with R = 2^16; constants stored as c · R mod q multiply to plain products.
internal static class MLKemConstants
{
	internal const int N = 256;

	internal const short Q = 3329;

	// q⁻¹ mod 2^16, signed.
	internal const short QInverse = -3327;

	// R² mod q; Montgomery multiplication by it multiplies by R.
	internal const short RSquared = 1353;

	// RSquared · q⁻¹ mod 2^16.
	internal const short RSquaredQInverse = 20553;

	// R² / 128 mod q, which ends NTT⁻¹ (Algorithm 10, line 14) by dividing by 128 and multiplying by R.
	internal const short InverseNttFactor = 1441;

	// InverseNttFactor · q⁻¹ mod 2^16.
	internal const short InverseNttFactorQInverse = -10079;

	// Zetas[1] · InverseNttFactor · R⁻¹ mod q and its product with q⁻¹ mod 2^16: the zeta of the last layer of NTT⁻¹ and the factor
	// that ends it, which MLKemAvx2 and MLKemAvx512 apply in one Montgomery product.
	internal const short LastInverseZeta = 1397;

	internal const short LastInverseZetaQInverse = 5237;

	// 2^26 / q rounded: (a · 20159 + 2^25) >> 26 is a / q rounded for every 16-bit a.
	internal const int BarrettMultiplier = 20159;

	// ⌈2^34 / (2q)⌉: (n · M) >> 34 is ⌊n / (2q)⌋ for n = 2^(d + 1) · x + q with d ≤ 11, which gives Compress_d(x).
	internal const ulong CompressMultiplier = 2580335;

	internal const int CompressShift = 34;

	// ζ^BitRev7(i) · R mod q for ζ = 17, centered on zero. In MultiplyNTTs (Algorithm 11), pairs 4i and 4i + 1 multiply modulo
	// X² − γ with γ at entry 64 + i, and pairs 4i + 2 and 4i + 3 modulo X² + γ.
	internal static ReadOnlySpan<short> Zetas =>
	[
		-1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
		573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
		1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
		-853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
		-1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653,
		-246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75,
		817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
		-1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628
	];
}
