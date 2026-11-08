namespace CryptoBase.EllipticCurves.SM9;

// The R-ate pairing e: G1 × G2 → GT of GM/T 0044.1 B.6.2 with a = 6t + 2, as GM/T 0044.2 to 0044.4 take it: e(P, Q) for P of G1 and Q of G2, neither the point at infinity. Its values match those of GM/T 0044.5. Neither the time nor the addresses depend on P or Q, so Q may be a private key.
internal static class SM9Pairing
{
	internal static void Pair(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		SM9KernelDispatch.MillerLoop(in p, in q, out SM9Fp12 f);
		SM9KernelDispatch.FinalExponentiation(in f, out result);
		f.ZeroMemory();
	}
}

// The lines of the Miller loop for a fixed Q of G2, which make e(P, Q) cheaper for each P. Q may be a private key, whose lines are as secret as it is: Dispose erases them.
internal sealed class SM9PairingLines : IDisposable
{
	private readonly SM9PrecomputedLine[] _lines = new SM9PrecomputedLine[SM9MillerLoop.LineCount];

	internal SM9PairingLines(in SM9AffinePoint<SM9Fp2> q)
	{
		SM9MillerLoop.Precompute(in q, _lines);
	}

	// The lines of P2, which every product with them shares.
	internal static SM9PairingLines Generator => GeneratorLines.Value;

	// e(P, Q) for a public P of G1, other than the point at infinity: the factors of P take an inversion in variable time, so the time depends on P, but neither it nor the addresses depend on Q.
	internal void PairVariableTime(in SM9AffinePoint<SM9Fp> p, out SM9Fp12 result)
	{
		SM9MillerLoop.FactorsVariableTime(in p, out SM9Fp alpha, out SM9Fp beta);
		SM9KernelDispatch.MillerLoop(in alpha, in beta, _lines, out SM9Fp12 f);
		SM9KernelDispatch.FinalExponentiation(in f, out result);
		f.ZeroMemory();
	}

	// e(P, Q)·e(P′, Q′) for the Q′ of other and public P and P′ of G1 in projective form, P not the point at infinity and P′ perhaps, whose pairing is then 1: one Miller loop and one final exponentiation, with the factors of both points from one inversion, in variable time.
	internal void PairVariableTime(in SM9Point<SM9Fp> p, SM9PairingLines other, in SM9Point<SM9Fp> otherPoint, out SM9Fp12 result)
	{
		SM9Fp12 f;

		if (SM9Fp.IsZero(in otherPoint.Z) is not 0)
		{
			SM9MillerLoop.FactorsVariableTime(in p, out SM9Fp alpha, out SM9Fp beta);
			SM9KernelDispatch.MillerLoop(in alpha, in beta, _lines, out f);
		}
		else
		{
			SM9MillerLoop.FactorsVariableTime(in p, in otherPoint, out SM9Fp alpha, out SM9Fp beta, out SM9Fp otherAlpha, out SM9Fp otherBeta);
			SM9KernelDispatch.MillerLoop(in alpha, in beta, _lines, in otherAlpha, in otherBeta, other._lines, out f);
		}

		SM9KernelDispatch.FinalExponentiation(in f, out result);
		f.ZeroMemory();
	}

	public void Dispose()
	{
		_lines.AsSpan().ZeroMemory();
	}

	// Built at the first use of Generator.
	private static class GeneratorLines
	{
		internal static readonly SM9PairingLines Value = new(in SM9G2.Generator);
	}
}
