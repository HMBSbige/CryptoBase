namespace CryptoBase.EllipticCurves.SM9;

// The scalar arithmetic of G2, the subgroup of order N of E'(Fp2), E': y² = x³ + 5u, with the generator P2 of GM/T 0044.5 §3.1. E'(Fp2) has order N·h with h = 2p − N, which is prime to N, so a point of the twist need not lie in G2. Scalars are plain values below N, and the products give projective points that a caller makes affine or erases.
// ψ(x, y) = (x̄·cx, ȳ·cy), cx = w^(2(1 − p)) and cy = w^(3(1 − p)) in Fp, is the p-power Frobenius of E(Fp12) carried to the twist through ψ6(x, y) = (x·w⁻², y·w⁻³). It is an endomorphism of E'(Fp2) with ψ² − tr·ψ + p = 0, tr = 6t² + 1 the trace of E, and it acts on G2 as [p]. As cy² = −1, ψ²(x, y) = (x·cx², −y).
internal static class SM9G2Group
{
	// The plain coordinates of P2: x0, x1, y0 and y1 in 64-bit limbs.
	private static ReadOnlySpan<ulong> GeneratorX0 => [0xF9B7213BAF82D65B, 0xEE265948D19C17AB, 0xD2AAB97FD34EC120, 0x3722755292130B08];

	private static ReadOnlySpan<ulong> GeneratorX1 => [0x54806C11D8806141, 0xF1DD2C190F5E93C4, 0x597B6027B441A01F, 0x85AEF3D078640C98];

	private static ReadOnlySpan<ulong> GeneratorY0 => [0x6215BBA5C999A7C7, 0x47EFBA98A71A0811, 0x5F3170153D278FF2, 0xA7CF28D519BE3DA6];

	private static ReadOnlySpan<ulong> GeneratorY1 => [0x856DC76B84EBEB96, 0x0736A96FA347C8BD, 0x66BA0D262CBEE6ED, 0x17509B092E845C12];

	// cx, cy and cx² in Montgomery form.
	private static ReadOnlySpan<ulong> FrobeniusXLimbs => [0x0005E42D3C846B19, 0x000178A102D42965, 0x000D52233DF8685E, 0x00002E356B46DE0E, 0x0000B1EC18B76DBE];

	private static ReadOnlySpan<ulong> FrobeniusYLimbs => [0x000B8B3A7FFF7A46, 0x000CAED3697E2F0C, 0x000305C78A2B004E, 0x00075DE2EDEB35A2, 0x000072F113DADB66];

	private static ReadOnlySpan<ulong> FrobeniusXSquaredLimbs => [0x000D399AC58063D7, 0x0008BD0A0B4284DE, 0x000797432EE34106, 0x0005BABBB0526C00, 0x00005B6C18B7A7CE];

	// a = 6t + 2 = 0x2400000000215D93E in 64-bit limbs.
	internal static ReadOnlySpan<ulong> LoopScalar => [0x400000000215D93E, 0x2];

	internal static readonly SM9AffinePoint<SM9Fp2> Generator = FromPlain();

	// Windows of width 5, 52 of 16 entries.
	internal static readonly SM9BaseTable<SM9Fp2> BaseTable = new(in Generator, 5);

	// k·P2 by BaseTable. Neither the time nor the addresses depend on k.
	[SkipLocalsInit]
	internal static void MultiplyBase(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
	{
		BaseTable.Multiply(in scalar, out result);
	}

	// k·P2 + addend for a public k and addend.
	[SkipLocalsInit]
	internal static void MultiplyBaseAddVariableTime(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
	{
		BaseTable.MultiplyAddVariableTime(in scalar, in addend, out result);
	}

	// Whether a point of E'(Fp2) lies in G2: α(Q) = [a]Q + ψ(Q) − ψ²(Q) + ψ³(Q) for a = 6t + 2. On G2, α acts as a + p − p² + p³ ≡ 0 (mod N), so α(G2) = O. Conversely, ψ² = tr·ψ − p on E'(Fp2) reduces α to α0 + α1·ψ, whose product with its conjugate (α0 + α1·tr) − α1·ψ is the integer n = α0² + α0·α1·tr + α1²·p; α(Q) = O then gives n·Q = O, and as N divides n while n is prime to h = 2p − N, the order of Q divides N. So α(Q) = O just for Q in G2, and the test takes one product by a 66-bit scalar, that of the kernel, and three Frobenius maps rather than a product by N.
	// The time depends only on the public scalar a, so the point may be a private key; the multiples and images in its locals are erased.
	[SkipLocalsInit]
	internal static bool IsInSubgroupVariableTime(in SM9AffinePoint<SM9Fp2> point)
	{
		SM9Curve<SM9Fp2>.FromAffine(in point, out SM9Point<SM9Fp2> q);
		SM9KernelDispatch.MultiplyByLoopScalarG2(in q, out SM9Point<SM9Fp2> sum);
		Frobenius(in q, out SM9Point<SM9Fp2> frobenius);
		SM9Curve<SM9Fp2>.Add(in sum, in frobenius, out sum);
		Frobenius(in frobenius, out frobenius);
		Frobenius(in frobenius, out SM9Point<SM9Fp2> cube);
		SM9Curve<SM9Fp2>.Add(in sum, in cube, out sum);
		bool inSubgroup = SM9Curve<SM9Fp2>.AreEqual(in sum, in frobenius) is not 0;
		q.ZeroMemory();
		sum.ZeroMemory();
		frobenius.ZeroMemory();
		cube.ZeroMemory();
		return inSubgroup;
	}

	// ψ(X : Y : Z) = (X̄·cx : Ȳ·cy : Z̄), each coordinate in place in result, which may be point, so that no local holds a copy of one.
	[SkipLocalsInit]
	internal static void Frobenius(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
	{
		SM9Fp2.Conjugate(in point.X, out result.X);
		SM9Fp2.MultiplyByFp(in result.X, in SM9Fp.FromConstant(FrobeniusXLimbs), out result.X);
		SM9Fp2.Conjugate(in point.Y, out result.Y);
		SM9Fp2.MultiplyByFp(in result.Y, in SM9Fp.FromConstant(FrobeniusYLimbs), out result.Y);
		SM9Fp2.Conjugate(in point.Z, out result.Z);
	}

	// ψ(x, y) = (x̄·cx, ȳ·cy), as above.
	[SkipLocalsInit]
	internal static void Frobenius(in SM9AffinePoint<SM9Fp2> point, out SM9AffinePoint<SM9Fp2> result)
	{
		SM9Fp2.Conjugate(in point.X, out result.X);
		SM9Fp2.MultiplyByFp(in result.X, in SM9Fp.FromConstant(FrobeniusXLimbs), out result.X);
		SM9Fp2.Conjugate(in point.Y, out result.Y);
		SM9Fp2.MultiplyByFp(in result.Y, in SM9Fp.FromConstant(FrobeniusYLimbs), out result.Y);
	}

	// −ψ²(x, y) = (x·cx², y).
	[SkipLocalsInit]
	internal static void NegatedFrobeniusSquared(in SM9AffinePoint<SM9Fp2> point, out SM9AffinePoint<SM9Fp2> result)
	{
		result.Y = point.Y;
		SM9Fp2.MultiplyByFp(in point.X, in SM9Fp.FromConstant(FrobeniusXSquaredLimbs), out result.X);
	}

	[SkipLocalsInit]
	private static SM9AffinePoint<SM9Fp2> FromPlain()
	{
		SM9AffinePoint<SM9Fp2> point;
		SM9Fp.FromLimbs(GeneratorX0, out point.X.A0);
		SM9Fp.FromLimbs(GeneratorX1, out point.X.A1);
		SM9Fp.FromLimbs(GeneratorY0, out point.Y.A0);
		SM9Fp.FromLimbs(GeneratorY1, out point.Y.A1);
		SM9Fp2.ToMontgomery(in point.X, out point.X);
		SM9Fp2.ToMontgomery(in point.Y, out point.Y);
		return point;
	}
}
