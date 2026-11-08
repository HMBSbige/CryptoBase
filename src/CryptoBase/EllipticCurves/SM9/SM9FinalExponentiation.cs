namespace CryptoBase.EllipticCurves.SM9;

// f^((p¹² − 1)/N), exactly, for f ≠ 0, as GM/T 0044.1 B.6.2 step g) takes it. (p¹² − 1)/N = (p⁶ − 1)(p² + 1)·(p⁴ − p² + 1)/N: the easy part f^((p⁶ − 1)(p² + 1)) takes one inversion and Frobenius maps and leaves an element of the cyclotomic subgroup, where inverses are conjugates and squares take the cyclotomic formula. The hard part (p⁴ − p² + 1)/N is λ0 + λ1·p + λ2·p² + λ3·p³ with λ3 = 1, λ2 = 6t² + 1, λ1 = −36t³ − 18t² − 12t + 1 and λ0 = −36t³ − 30t² − 18t − 2 (Scott, Benger, Charlemagne, Dominguez Perez and Kachisa, "On the final exponentiation for calculating pairings on ordinary elliptic curves", 2009), the exponent itself rather than a multiple of it: with the powers f^t, f^(t²) and f^(t³), it is y0·y1²·y2⁶·y3¹²·y4¹⁸·y5³⁰·y6³⁶ for y0 = f^(p + p² + p³), y1 = f⁻¹, y2 = f^(t²p²), y3 = f^(−tp), y4 = f^(−t − t²p), y5 = f^(−t²) and y6 = f^(−t³ − t³p), whose exponents sum to the λ.
// Neither the time nor the addresses depend on f, and the intermediates are erased.
internal static class SM9FinalExponentiation
{
	// The NAF of t = 0x600000000058F98A: the digits +1 and −1, least significant first, with the top +1 at bit 63.
	internal const ulong TPlus = 0x800000000081020A;

	internal const ulong TMinus = 0x2000000000280880;

	[SkipLocalsInit]
	internal static void Run(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9Fp12.Invert(in value, out SM9Fp12 inverse);
		SM9Fp12.Conjugate(in value, out SM9Fp12 f);
		SM9Fp12.Multiply(in f, in inverse, out f);
		SM9Fp12.FrobeniusSquared(in f, out SM9Fp12 t0);
		SM9Fp12.Multiply(in t0, in f, out f);
		PowerT(in f, out SM9Fp12 ft);
		PowerT(in ft, out SM9Fp12 ft2);
		PowerT(in ft2, out SM9Fp12 ft3);
		// y0 = f^p·f^(p²)·f^(p³).
		SM9Fp12.Frobenius(in f, out SM9Fp12 y0);
		SM9Fp12.FrobeniusSquared(in f, out t0);
		SM9Fp12.Multiply(in y0, in t0, out y0);
		SM9Fp12.FrobeniusCubed(in f, out t0);
		SM9Fp12.Multiply(in y0, in t0, out y0);
		// y1 = conj(f), y2 = (f^(t²))^(p²), y3 = conj((f^t)^p), y4 = conj(f^t·(f^(t²))^p), y5 = conj(f^(t²)) and y6 = conj(f^(t³)·(f^(t³))^p).
		SM9Fp12.Conjugate(in f, out SM9Fp12 y1);
		SM9Fp12.FrobeniusSquared(in ft2, out SM9Fp12 y2);
		SM9Fp12.Frobenius(in ft, out SM9Fp12 y3);
		SM9Fp12.Conjugate(in y3, out y3);
		SM9Fp12.Frobenius(in ft2, out SM9Fp12 y4);
		SM9Fp12.Multiply(in y4, in ft, out y4);
		SM9Fp12.Conjugate(in y4, out y4);
		SM9Fp12.Conjugate(in ft2, out SM9Fp12 y5);
		SM9Fp12.Frobenius(in ft3, out SM9Fp12 y6);
		SM9Fp12.Multiply(in y6, in ft3, out y6);
		SM9Fp12.Conjugate(in y6, out y6);
		// The vectorial addition chain: T0 = y6²·y4·y5, T1 = y3·y5·T0, T0 = T0·y2, T1 = (T1²·T0)², and the result (T1·y0)·(T1·y1)².
		SM9Fp12.CyclotomicSquare(in y6, out t0);
		SM9Fp12.Multiply(in t0, in y4, out t0);
		SM9Fp12.Multiply(in t0, in y5, out t0);
		SM9Fp12.Multiply(in y3, in y5, out SM9Fp12 t1);
		SM9Fp12.Multiply(in t1, in t0, out t1);
		SM9Fp12.Multiply(in t0, in y2, out t0);
		SM9Fp12.CyclotomicSquare(in t1, out t1);
		SM9Fp12.Multiply(in t1, in t0, out t1);
		SM9Fp12.CyclotomicSquare(in t1, out t1);
		SM9Fp12.Multiply(in t1, in y1, out t0);
		SM9Fp12.Multiply(in t1, in y0, out t1);
		SM9Fp12.CyclotomicSquare(in t0, out t0);
		SM9Fp12.Multiply(in t1, in t0, out result);
		inverse.ZeroMemory();
		f.ZeroMemory();
		t0.ZeroMemory();
		t1.ZeroMemory();
		ft.ZeroMemory();
		ft2.ZeroMemory();
		ft3.ZeroMemory();
		y0.ZeroMemory();
		y1.ZeroMemory();
		y2.ZeroMemory();
		y3.ZeroMemory();
		y4.ZeroMemory();
		y5.ZeroMemory();
		y6.ZeroMemory();
	}

	// value^t for value in the cyclotomic subgroup, by the NAF of t, which is public.
	[SkipLocalsInit]
	private static void PowerT(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9Fp12.Conjugate(in value, out SM9Fp12 inverse);
		SM9Fp12 power = value;

		for (int i = 62; i >= 0; --i)
		{
			SM9Fp12.CyclotomicSquare(in power, out power);

			if ((TPlus >> i & 1) is not 0)
			{
				SM9Fp12.Multiply(in power, in value, out power);
			}
			else if ((TMinus >> i & 1) is not 0)
			{
				SM9Fp12.Multiply(in power, in inverse, out power);
			}
		}

		result = power;
		inverse.ZeroMemory();
		power.ZeroMemory();
	}
}
