namespace CryptoBase.EllipticCurves.SM9;

// The Miller loop of the R-ate pairing of GM/T 0044.1 B.6.2 for P of G1 and Q of G2, with a = 6t + 2 in its NAF: f_{a,Q}(P), then the lines to π(Q) and −π²(Q). The points of the twist stand for those of E(Fp12) through ψ6(x, y) = (x·w⁻², y·w⁻³), and the lines differ from those of the standard by factors in Fp2 and Fp4 = Fp2(w³), as do the vertical lines that the NAF and the projective coordinates leave out: the final exponentiation, (p¹² − 1)/N, is a multiple of p⁴ − 1 and of p⁶ − 1, so it maps all of them to 1, and the pairing comes out as the standard's.
// T runs through the multiples of Q in homogeneous projective coordinates, by the formulas of Costello, Lange and Naehrig ("Faster pairing computations on curves with high-degree twists", 2010) for a = 0, which need T ≠ ±Q: T is a multiple kQ with 2 ≤ k ≤ a < N − 1 in the loop, a + p ≢ 0 and a + p ± p² ≢ 0 (mod N) at the end, as a + p − p² ≡ −p³, so none of the points is at infinity and no addition meets its double or its negation, for Q of G2 other than the point at infinity.
// Neither the time nor the addresses depend on P or Q, and the points and lines in its locals are erased.
internal static class SM9MillerLoop
{
	// The lines of the loop: one doubling for each digit below the top one, an addition for each nonzero digit below the top one, and the two of the end.
	internal const int LineCount = DoublingCount + AdditionCount + 2;

	private const int DoublingCount = 65;

	private const int AdditionCount = 10;

	// The NAF of a = 6t + 2 = 0x2400000000215D93E, least significant digit first.
	internal static ReadOnlySpan<sbyte> Digits =>
	[
		0, -1, 0, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,
	];

	[SkipLocalsInit]
	internal static void Run(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		SM9Fp.Negate(in p.X, out SM9Fp negatedX);
		SM9Fp y = p.Y;
		SM9AffinePoint<SM9Fp2> negatedQ;
		negatedQ.X = q.X;
		SM9Fp2.Negate(in q.Y, out negatedQ.Y);
		SM9Point<SM9Fp2> t;
		t.X = q.X;
		t.Y = q.Y;
		t.Z = SM9Fp2.One;
		ReadOnlySpan<sbyte> digits = Digits;
		Debug.Assert(digits[^2] is 0);

		// f starts at 1, so the first step, whose digit is 0, leaves f = l, an element of the form of a line.
		DoublingStep(ref t, out SM9Line line);
		FromLine(in line, in negatedX, in y, out SM9Fp12 f);

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Fp12.Square(in f, out f);
			DoublingStep(ref t, out line);
			MultiplyByLine(ref f, in line, in negatedX, in y);

			if (digits[i] > 0)
			{
				AdditionStep(ref t, in q, out line);
				MultiplyByLine(ref f, in line, in negatedX, in y);
			}
			else if (digits[i] < 0)
			{
				AdditionStep(ref t, in negatedQ, out line);
				MultiplyByLine(ref f, in line, in negatedX, in y);
			}
		}

		SM9G2Group.Frobenius(in q, out SM9AffinePoint<SM9Fp2> q1);
		AdditionStep(ref t, in q1, out line);
		MultiplyByLine(ref f, in line, in negatedX, in y);
		SM9G2Group.NegatedFrobeniusSquared(in q, out SM9AffinePoint<SM9Fp2> q2);
		AdditionStep(ref t, in q2, out line);
		MultiplyByLine(ref f, in line, in negatedX, in y);
		result = f;
		negatedX.ZeroMemory();
		y.ZeroMemory();
		negatedQ.ZeroMemory();
		t.ZeroMemory();
		line.ZeroMemory();
		q1.ZeroMemory();
		q2.ZeroMemory();
		f.ZeroMemory();
	}

	// The LineCount lines of Q, in the order Run takes them, divided by their L3, for a Q of G2 other than the point at infinity: L3 is 2YZ for a doubling, where Y ≠ 0 as G2 has no point of order 2 and Z ≠ 0 as T is not the point at infinity, and λ = X − x_Q·Z for an addition, which is 0 only where T = ±Q, which no addition meets. (L0 : −L2 : L3) as a projective point has the affine form (L0/L3, −L2/L3), which the kernel's ToAffine writes into the lines, of the layout of SM9AffinePoint, for all of them with one inversion, in constant time. The time and the addresses do not depend on Q, and the steps in its locals are erased.
	[SkipLocalsInit]
	internal static void Precompute(in SM9AffinePoint<SM9Fp2> q, Span<SM9PrecomputedLine> lines)
	{
		Debug.Assert(lines.Length is LineCount);

		Span<SM9Point<SM9Fp2>> steps = stackalloc SM9Point<SM9Fp2>[LineCount];
		SM9AffinePoint<SM9Fp2> negatedQ;
		negatedQ.X = q.X;
		SM9Fp2.Negate(in q.Y, out negatedQ.Y);
		SM9Point<SM9Fp2> t;
		t.X = q.X;
		t.Y = q.Y;
		t.Z = SM9Fp2.One;
		ReadOnlySpan<sbyte> digits = Digits;
		Unsafe.SkipInit(out SM9Line line);
		int k = 0;

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			DoublingStep(ref t, out line);
			Keep(in line, steps, k++);

			if (digits[i] > 0)
			{
				AdditionStep(ref t, in q, out line);
				Keep(in line, steps, k++);
			}
			else if (digits[i] < 0)
			{
				AdditionStep(ref t, in negatedQ, out line);
				Keep(in line, steps, k++);
			}
		}

		SM9G2Group.Frobenius(in q, out SM9AffinePoint<SM9Fp2> q1);
		AdditionStep(ref t, in q1, out line);
		Keep(in line, steps, k++);
		SM9G2Group.NegatedFrobeniusSquared(in q, out SM9AffinePoint<SM9Fp2> q2);
		AdditionStep(ref t, in q2, out line);
		Keep(in line, steps, k);
		SM9KernelDispatch.ToAffine(steps, MemoryMarshal.Cast<SM9PrecomputedLine, SM9AffinePoint<SM9Fp2>>(lines), false);
		steps.ZeroMemory();
		negatedQ.ZeroMemory();
		t.ZeroMemory();
		line.ZeroMemory();
		q1.ZeroMemory();
		q2.ZeroMemory();
	}

	// As Run, with the lines of Q from Precompute, each at P by the factors α = 1/yP and β = xP·α of P that FactorsVariableTime gives.
	[SkipLocalsInit]
	internal static void Run(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
	{
		Debug.Assert(lines.Length is LineCount);

		ReadOnlySpan<sbyte> digits = Digits;
		Debug.Assert(digits[^2] is 0);

		// f starts at 1, so the first step, whose digit is 0, leaves f = l0 + l2·w² + w³, the first line.
		SM9Fp12 f = default;
		Evaluate(in lines[0], in alpha, in beta, out f.C0.C0, out f.C0.C1);
		f.C1.C1 = SM9Fp2.One;
		int k = 1;

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Fp12.Square(in f, out f);
			MultiplyByLine(ref f, in lines[k++], in alpha, in beta);

			if (digits[i] is not 0)
			{
				MultiplyByLine(ref f, in lines[k++], in alpha, in beta);
			}
		}

		MultiplyByLine(ref f, in lines[k++], in alpha, in beta);
		MultiplyByLine(ref f, in lines[k], in alpha, in beta);
		result = f;
		f.ZeroMemory();
	}

	// The product of Run for P with the lines of one Q and for P′ with those of another, which share the squares, from the factors of each point: each step takes the line of each.
	[SkipLocalsInit]
	internal static void Run(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
	{
		Debug.Assert(lines.Length is LineCount && otherLines.Length is LineCount);

		ReadOnlySpan<sbyte> digits = Digits;
		Debug.Assert(digits[^2] is 0);

		SM9Fp12 f = default;
		Evaluate(in lines[0], in alpha, in beta, out f.C0.C0, out f.C0.C1);
		f.C1.C1 = SM9Fp2.One;
		MultiplyByLine(ref f, in otherLines[0], in otherAlpha, in otherBeta);
		int k = 1;

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Fp12.Square(in f, out f);
			MultiplyByLine(ref f, in lines[k], in alpha, in beta);
			MultiplyByLine(ref f, in otherLines[k++], in otherAlpha, in otherBeta);

			if (digits[i] is not 0)
			{
				MultiplyByLine(ref f, in lines[k], in alpha, in beta);
				MultiplyByLine(ref f, in otherLines[k++], in otherAlpha, in otherBeta);
			}
		}

		for (; k < LineCount; ++k)
		{
			MultiplyByLine(ref f, in lines[k], in alpha, in beta);
			MultiplyByLine(ref f, in otherLines[k], in otherAlpha, in otherBeta);
		}

		result = f;
		f.ZeroMemory();
	}

	// α = 1/yP and β = xP/yP, the factors of the lines of Precompute at a public P; the inversion takes variable time.
	[SkipLocalsInit]
	internal static void FactorsVariableTime(in SM9AffinePoint<SM9Fp> p, out SM9Fp alpha, out SM9Fp beta)
	{
		SM9Fp.InvertVariableTime(in p.Y, out alpha);
		SM9Fp.Multiply(in p.X, in alpha, out beta);
	}

	// The factors α = Z/Y and β = X/Y of public P and P′ in projective form, neither the point at infinity, whose Y are then not 0 as G1 has no point of order 2: one inversion of Y·Y′, in variable time, takes both.
	[SkipLocalsInit]
	internal static void FactorsVariableTime(in SM9Point<SM9Fp> p, in SM9Point<SM9Fp> other, out SM9Fp alpha, out SM9Fp beta, out SM9Fp otherAlpha, out SM9Fp otherBeta)
	{
		SM9Fp.Multiply(in p.Y, in other.Y, out SM9Fp inverse);
		SM9Fp.InvertVariableTime(in inverse, out inverse);
		SM9Fp.Multiply(in other.Y, in inverse, out SM9Fp yInverse);
		SM9Fp.Multiply(in p.Y, in inverse, out SM9Fp otherYInverse);
		SM9Fp.Multiply(in p.Z, in yInverse, out alpha);
		SM9Fp.Multiply(in p.X, in yInverse, out beta);
		SM9Fp.Multiply(in other.Z, in otherYInverse, out otherAlpha);
		SM9Fp.Multiply(in other.X, in otherYInverse, out otherBeta);
	}

	// As above for one point.
	[SkipLocalsInit]
	internal static void FactorsVariableTime(in SM9Point<SM9Fp> p, out SM9Fp alpha, out SM9Fp beta)
	{
		SM9Fp.InvertVariableTime(in p.Y, out SM9Fp inverse);
		SM9Fp.Multiply(in p.Z, in inverse, out alpha);
		SM9Fp.Multiply(in p.X, in inverse, out beta);
	}

	// l0 = A·α and l2 = B·β of a line of Precompute at P.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Evaluate(in SM9PrecomputedLine line, in SM9Fp alpha, in SM9Fp beta, out SM9Fp2 l0, out SM9Fp2 l2)
	{
		SM9Fp2.MultiplyByFp(in line.A, in alpha, out l0);
		SM9Fp2.MultiplyByFp(in line.B, in beta, out l2);
	}

	// A line as the point (L0 : −L2 : L3) into steps[k], for Precompute.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Keep(in SM9Line line, Span<SM9Point<SM9Fp2>> steps, int k)
	{
		steps[k].X = line.L0;
		SM9Fp2.Negate(in line.L2, out steps[k].Y);
		steps[k].Z = line.L3;
	}

	// T = 2T. With A = XY, B = Y², C = Z², E = 3b'·C, F = 3E and H = 2YZ, 2T = (2A(B − F) : (B + F)² − 12E² : 4BH), four times the point of the formula of Costello, Lange and Naehrig with A = XY/2, which needs no halving. The tangent at T, scaled by 2YZ² and by w³ in Fp4 and divided by Z, and with Y²Z = X³ + b'Z³ to remove X³, is (B − E) − 3X²·xP·w² + H·yP·w³.
	// The factors 2, 3, 4 and 12 and the difference of Y3 act on the products before their reduction. For reduced X, Y, Z, so reduced A to F and H, and B − F as B + 3p − F below 5.25p in limbs below 2^54: 3X² has coefficients in (−31p², 31p²), 2YZ in (−21p², 21p²), 2A(B − F) in (−48p², 48p²), (B + F)² − 12E², with B + F below 4.5p in limbs below 2^53, in (−122p², 142p²), and 4BH in (−41p², 41p²), all within SM9Fp.ReduceWide, as are the columns, below 2^61.4.
	[SkipLocalsInit]
	internal static void DoublingStep(ref SM9Point<SM9Fp2> t, out SM9Line line)
	{
		SM9Fp2.Multiply(in t.X, in t.Y, out SM9Fp2 a);
		SM9Fp2.Square(in t.Y, out SM9Fp2 b);
		SM9Fp2.Square(in t.Z, out SM9Fp2 c);
		SM9Fp2.MultiplyByThreeB(in c, out SM9Fp2 e);
		SM9Fp2.MultiplySmall(in e, 3, out SM9Fp2 f);
		Unsafe.SkipInit(out line);
		SM9Fp2.Subtract(in b, in e, out line.L0);
		SM9Fp2.SquareWide(in t.X, out SM9Fp2Wide wide);
		SM9Fp2Wide.MultiplySmall(in wide, 3, out wide);
		SM9Fp2Wide.Reduce(in wide, out line.L2);
		SM9Fp2.MultiplyWide(in t.Y, in t.Z, out wide);
		SM9Fp2Wide.MultiplySmall(in wide, 2, out wide);
		SM9Fp2Wide.Reduce(in wide, out line.L3);
		SM9Fp2.SubtractUnreduced(in b, in f, out c);
		SM9Fp2.MultiplyWide(in a, in c, out wide);
		SM9Fp2Wide.MultiplySmall(in wide, 2, out wide);
		SM9Fp2Wide.Reduce(in wide, out t.X);
		SM9Fp2.AddUnreduced(in b, in f, out c);
		SM9Fp2.SquareWide(in c, out wide);
		SM9Fp2.SquareWide(in e, out SM9Fp2Wide square);
		SM9Fp2Wide.SubtractMultiple(in wide, in square, 12, out wide);
		SM9Fp2Wide.Reduce(in wide, out t.Y);
		SM9Fp2.MultiplyWide(in b, in line.L3, out wide);
		SM9Fp2Wide.MultiplySmall(in wide, 4, out wide);
		SM9Fp2Wide.Reduce(in wide, out t.Z);
	}

	// T = T + Q for an affine Q. With θ = Y − y_Q·Z, λ = X − x_Q·Z, C = θ², D = λ², E = λ³, F = Z·C, G = X·D and H = E + F − 2G, T + Q = (λH : θ(G − H) − Y·E : Z·E). The line through T and Q, scaled by λ and by w³, is (θ·x_Q − λ·y_Q) − θ·xP·w² + λ·yP·w³.
	// The differences of products act before their reduction: for reduced inputs θ·x_Q − λ·y_Q has coefficients in (−16p², 16p²) and θ(G − H) − Y·E, with G − H as G + 3p − H below 5.25p, in (−29p², 24p²).
	[SkipLocalsInit]
	internal static void AdditionStep(ref SM9Point<SM9Fp2> t, in SM9AffinePoint<SM9Fp2> q, out SM9Line line)
	{
		SM9Fp2.Multiply(in q.Y, in t.Z, out SM9Fp2 theta);
		SM9Fp2.Subtract(in t.Y, in theta, out theta);
		SM9Fp2.Multiply(in q.X, in t.Z, out SM9Fp2 lambda);
		SM9Fp2.Subtract(in t.X, in lambda, out lambda);
		SM9Fp2.Square(in theta, out SM9Fp2 c);
		SM9Fp2.Square(in lambda, out SM9Fp2 d);
		SM9Fp2.Multiply(in lambda, in d, out SM9Fp2 e);
		SM9Fp2.Multiply(in t.Z, in c, out SM9Fp2 f);
		SM9Fp2.Multiply(in t.X, in d, out SM9Fp2 g);
		SM9Fp2.SumMinusTwice(in e, in f, in g, out SM9Fp2 h);
		Unsafe.SkipInit(out line);
		SM9Fp2.MultiplyWide(in theta, in q.X, out SM9Fp2Wide wide);
		SM9Fp2.MultiplyWide(in lambda, in q.Y, out SM9Fp2Wide product);
		SM9Fp2Wide.Subtract(in wide, in product, out wide);
		SM9Fp2Wide.Reduce(in wide, out line.L0);
		line.L2 = theta;
		line.L3 = lambda;
		SM9Fp2.SubtractUnreduced(in g, in h, out g);
		SM9Fp2.MultiplyWide(in theta, in g, out wide);
		SM9Fp2.MultiplyWide(in t.Y, in e, out product);
		SM9Fp2Wide.Subtract(in wide, in product, out wide);
		SM9Fp2Wide.Reduce(in wide, out t.Y);
		SM9Fp2.Multiply(in lambda, in h, out t.X);
		SM9Fp2.Multiply(in t.Z, in e, out t.Z);
	}

	// f = f·l for the line at P, given −xP and yP.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyByLine(ref SM9Fp12 f, in SM9Line line, in SM9Fp negatedX, in SM9Fp y)
	{
		SM9Fp2.MultiplyByFp(in line.L2, in negatedX, out SM9Fp2 l2);
		SM9Fp2.MultiplyByFp(in line.L3, in y, out SM9Fp2 l3);
		SM9Fp12.MultiplyByLine(in f, in line.L0, in l2, in l3, out f);
	}

	// f = f·l for a line of Precompute at P, given α and β.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyByLine(ref SM9Fp12 f, in SM9PrecomputedLine line, in SM9Fp alpha, in SM9Fp beta)
	{
		Evaluate(in line, in alpha, in beta, out SM9Fp2 l0, out SM9Fp2 l2);
		SM9Fp12.MultiplyByNormalizedLine(in f, in l0, in l2, out f);
	}

	// The line at P as an element of Fp12: C0 = (l0, l2, 0) and C1 = (0, l3, 0).
	[SkipLocalsInit]
	private static void FromLine(in SM9Line line, in SM9Fp negatedX, in SM9Fp y, out SM9Fp12 result)
	{
		result = default;
		result.C0.C0 = line.L0;
		SM9Fp2.MultiplyByFp(in line.L2, in negatedX, out result.C0.C1);
		SM9Fp2.MultiplyByFp(in line.L3, in y, out result.C1.C1);
	}
}
