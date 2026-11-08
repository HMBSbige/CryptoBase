namespace CryptoBase.EllipticCurves.SM9;

// The line of one step of the Miller loop before it meets P = (xP, yP) of G1: at P it is L0 − L2·xP·w² + L3·yP·w³, which SM9Fp12.MultiplyByLine takes as l0, l2 and l3. Its coefficients are reduced and in Montgomery form, and they may be secret, as those of a user's private key are.
internal struct SM9Line
{
	internal SM9Fp2 L0;
	internal SM9Fp2 L2;
	internal SM9Fp2 L3;
}

// A line of SM9MillerLoop.Precompute divided by its L3, which is never 0 there: A = L0/L3 and B = −L2/L3, so that at P it is A + B·xP·w² + yP·w³, and divided by yP too, A·α + B·β·w² + w³ for α = 1/yP and β = xP/yP, which a Miller loop with these lines takes; yP is not 0, as G1 has no point of order 2. Each differs from the line by a factor in Fp2, which the final exponentiation maps to 1 as it does the other factors of SM9MillerLoop. The coefficients are reduced and in Montgomery form, and as secret as the point of the line. A and B lie as x and y of SM9AffinePoint, through which Precompute writes them.
internal struct SM9PrecomputedLine
{
	internal SM9Fp2 A;
	internal SM9Fp2 B;
}
