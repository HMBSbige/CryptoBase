using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public class SM9TowerTest
{
	private const int RandomCount = 12;

	// Values with coefficients at the edges of the reduced range, each coefficient standing for some plain value in Montgomery form.
	private static List<SM9Fp2> Fp2Elements(Random random, int count)
	{
		List<SM9Fp> edges = EdgeElements();
		List<SM9Fp2> values = [];

		for (int i = 0; i < edges.Count; ++i)
		{
			values.Add(new SM9Fp2 { A0 = edges[i], A1 = edges[(i * 7 + 3) % edges.Count] });
		}

		for (int i = 0; i < count; ++i)
		{
			values.Add(new SM9Fp2 { A0 = Raw(RandomBelow(random, ReducedBound)), A1 = Raw(RandomBelow(random, ReducedBound)) });
		}

		return values;
	}

	[Test]
	public async Task Fp2MatchesTheReference()
	{
		List<string> failures = [];
		Random random = new(1);
		List<SM9Fp2> values = Fp2Elements(random, RandomCount);

		foreach (SM9Fp2 x in values)
		{
			Fp2Value vx = ValueOf(x);

			foreach (SM9Fp2 y in values)
			{
				Fp2Value vy = ValueOf(y);
				SM9Fp2.Multiply(in x, in y, out SM9Fp2 product);
				Check(failures, "Multiply", product, vx * vy);
				SM9Fp2.Add(in x, in y, out SM9Fp2 sum);
				Check(failures, "Add", sum, vx + vy);
				SM9Fp2.Subtract(in x, in y, out SM9Fp2 difference);
				Check(failures, "Subtract", difference, vx - vy);

				if (SM9Fp2.AreEqual(in x, in y) is not 0 != (vx == vy))
				{
					failures.Add($"AreEqual {vx}, {vy}");
				}
			}

			SM9Fp2.Square(in x, out SM9Fp2 square);
			Check(failures, "Square", square, vx * vx);
			SM9Fp2.MultiplyByU(in x, out SM9Fp2 timesU);
			Check(failures, "MultiplyByU", timesU, vx * U);
			SM9Fp2.MultiplyByThreeB(in x, out SM9Fp2 timesThreeB);
			Check(failures, "MultiplyByThreeB", timesThreeB, vx * TwistB * 3);
			SM9Fp2.Conjugate(in x, out SM9Fp2 conjugate);
			Check(failures, "Conjugate", conjugate, vx.Conjugate());
			SM9Fp2.Negate(in x, out SM9Fp2 negated);
			Check(failures, "Negate", negated, -vx);
			SM9Fp2.MultiplyByFp(in x, in x.A1, out SM9Fp2 scaled);
			Check(failures, "MultiplyByFp", scaled, vx * vx.A1);
			// The factor may be a coefficient of the result.
			SM9Fp2 overA0 = x;
			SM9Fp2.MultiplyByFp(in overA0, in overA0.A0, out overA0);
			Check(failures, "MultiplyByFp over A0", overA0, vx * vx.A0);
			SM9Fp2 overA1 = x;
			SM9Fp2.MultiplyByFp(in overA1, in overA1.A1, out overA1);
			Check(failures, "MultiplyByFp over A1", overA1, vx * vx.A1);
			SM9Fp2.Invert(in x, out SM9Fp2 inverse);
			SM9Fp2.InvertVariableTime(in x, out SM9Fp2 inverseVariableTime);
			Fp2Value expectedInverse = vx.IsZero ? Fp2Value.Zero : vx.Inverse();
			Check(failures, "Invert", inverse, expectedInverse);
			Check(failures, "InvertVariableTime", inverseVariableTime, expectedInverse);

			if (SM9Fp2.IsZero(in x) is not 0 != vx.IsZero)
			{
				failures.Add($"IsZero {vx}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// GM/T 0044.1 §7.2.6 and §7.2.7 put the u-coefficient first.
	[Test]
	public async Task Fp2EncodesTheUCoefficientFirst()
	{
		Fp2Value value = new(5, 7);
		SM9Fp2 element = new() { A0 = Raw(Mod(5 * MontgomeryR)), A1 = Raw(Mod(7 * MontgomeryR)) };
		byte[] encoded = new byte[SM9Fp2.ByteLength];
		SM9Fp2.ExportPlain(in element, encoded);
		bool valid = SM9Fp2.TryImport(encoded, out SM9Fp2 imported);
		byte[] tooLarge = [.. Encode(P), .. Encode(1)];

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(encoded)).IsEqualTo(Hex(value.A1) + Hex(value.A0));
			await Assert.That(valid).IsTrue();
			await Assert.That(RawValue(imported.A0)).IsEqualTo(5);
			await Assert.That(RawValue(imported.A1)).IsEqualTo(7);
			await Assert.That(SM9Fp2.TryImport(tooLarge, out SM9Fp2 rejected)).IsFalse();
			await Assert.That(SM9Fp2.IsZero(in rejected)).IsEqualTo(ulong.MaxValue);
		}
	}

	[Test]
	public async Task Fp12MatchesTheReference()
	{
		List<string> failures = [];
		Random random = new(2);
		List<Fp12Value> values = [Fp12Value.One, new(Enumerable.Repeat(new Fp2Value(P - 1, P - 1), 6).ToArray())];

		for (int i = 0; i < 6; ++i)
		{
			values.Add(RandomFp12(random));
		}

		foreach (Fp12Value x in values)
		{
			SM9Fp12 ex = Element(x);

			foreach (Fp12Value y in values)
			{
				SM9Fp12 ey = Element(y);
				SM9Fp12.Multiply(in ex, in ey, out SM9Fp12 product);
				Check(failures, "Multiply", product, x * y);
			}

			SM9Fp12.Square(in ex, out SM9Fp12 square);
			Check(failures, "Square", square, x * x);

			// A line l0 + l2·w² + l3·w³.
			Fp2Value l0 = RandomFp2(random);
			Fp2Value l2 = RandomFp2(random);
			Fp2Value l3 = RandomFp2(random);
			SM9Fp2 el0 = Element(l0);
			SM9Fp2 el2 = Element(l2);
			SM9Fp2 el3 = Element(l3);
			SM9Fp12.MultiplyByLine(in ex, in el0, in el2, in el3, out SM9Fp12 lined);
			Check(failures, "MultiplyByLine", lined, x * new Fp12Value([l0, Fp2Value.Zero, l2, l3, Fp2Value.Zero, Fp2Value.Zero]));
			SM9Fp12.Frobenius(in ex, out SM9Fp12 frobenius);
			Check(failures, "Frobenius", frobenius, x.Pow(P));
			SM9Fp12.FrobeniusSquared(in ex, out SM9Fp12 frobenius2);
			Check(failures, "FrobeniusSquared", frobenius2, x.Pow(P * P));
			SM9Fp12.FrobeniusCubed(in ex, out SM9Fp12 frobenius3);
			Check(failures, "FrobeniusCubed", frobenius3, x.Pow(P * P * P));
			SM9Fp12.Invert(in ex, out SM9Fp12 inverse);

			if (ValueOf(inverse) * x != Fp12Value.One || !IsReduced(inverse))
			{
				failures.Add($"Invert {x}");
			}

			SM9Fp12.Conjugate(in ex, out SM9Fp12 conjugate);
			Check(failures, "Conjugate", conjugate, new Fp12Value(x.C.Select((c, i) => i % 2 is 0 ? c : -c).ToArray()));

			// Results may be inputs.
			SM9Fp12 aliased = ex;
			SM9Fp12.Multiply(in aliased, in aliased, out aliased);
			Check(failures, "Multiply aliased", aliased, x * x);
			aliased = ex;
			SM9Fp12.MultiplyByLine(in aliased, in el0, in el2, in el3, out aliased);
			Check(failures, "MultiplyByLine aliased", aliased, x * new Fp12Value([l0, Fp2Value.Zero, l2, l3, Fp2Value.Zero, Fp2Value.Zero]));
		}

		await Assert.That(failures).IsEmpty();
	}

	// Elements f^((p⁶ − 1)(p² + 1)) lie in the cyclotomic subgroup, where the square of Granger and Scott holds.
	[Test]
	public async Task CyclotomicSquaresMatchSquares()
	{
		List<string> failures = [];
		Random random = new(3);

		for (int i = 0; i < 4; ++i)
		{
			Fp12Value f = RandomFp12(random);
			Fp12Value g = f.Pow((BigInteger.Pow(P, 6) - 1) * (P * P + 1));
			SM9Fp12 element = Element(g);
			SM9Fp12.CyclotomicSquare(in element, out SM9Fp12 square);
			Check(failures, "CyclotomicSquare", square, g * g);
			SM9Fp12.CyclotomicSquare(in element, out element);
			Check(failures, "CyclotomicSquare aliased", element, g * g);
		}

		await Assert.That(failures).IsEmpty();
	}

	// The lazy reductions add products before reducing them, so their bounds are tightest at coefficients of extreme raw values: 0, the largest reduced value and the one with limbs 0 to 3 all ones. Zero real parts with extreme u-parts make every product of Fp2 as negative as it gets, and random patterns of the extremes mix the cases.
	[Test]
	public async Task LazyReductionsHoldAtTheExtremes()
	{
		Random random = new(5);
		SM9Fp largest = Raw(ReducedBound - 1);
		SM9Fp ones = Raw((ReducedBound - 1 >> 208 << 208) - 1);
		SM9Fp zero = default;
		SM9Fp[] extremes = [zero, largest, ones];
		List<SM9Fp12> values = [Pattern(_ => largest), Pattern(i => i % 2 is 0 ? zero : largest), Pattern(i => i % 2 is 0 ? largest : zero), Pattern(i => i % 2 is 0 ? zero : ones), Pattern(_ => ones)];

		for (int k = 0; k < 24; ++k)
		{
			values.Add(Pattern(_ => extremes[random.Next(extremes.Length)]));
		}

		List<string> failures = [];

		foreach (SM9Fp12 x in values)
		{
			Fp12Value vx = ValueOf(x);

			foreach (SM9Fp12 y in values.Take(8))
			{
				Fp12Value vy = ValueOf(y);
				SM9Fp12.Multiply(in x, in y, out SM9Fp12 product);
				Check(failures, "Multiply", product, vx * vy);
				SM9Fp12.MultiplyByLine(in x, in y.C0.C0, in y.C0.C1, in y.C1.C1, out SM9Fp12 lined);
				Check(failures, "MultiplyByLine", lined, vx * new Fp12Value([vy.C[0], Fp2Value.Zero, vy.C[2], vy.C[3], Fp2Value.Zero, Fp2Value.Zero]));
			}

			SM9Fp12.Square(in x, out SM9Fp12 square);
			Check(failures, "Square", square, vx * vx);
			// The formula of the cyclotomic square, which holds as an identity of the coefficients for any input.
			SM9Fp12.CyclotomicSquare(in x, out SM9Fp12 cyclotomic);
			Check(failures, "CyclotomicSquare", cyclotomic, CyclotomicSquare(vx));
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task Fp12EncodesHighDimensionFirst()
	{
		Fp12Value value = RandomFp12(new Random(4));
		SM9Fp12 element = Element(value);
		byte[] encoded = new byte[SM9Fp12.ByteLength];
		SM9Fp12.Encode(in element, encoded);
		await Assert.That(Convert.ToHexString(encoded)).IsEqualTo(value.ToHex());
	}

	// The twelve coefficients of Fp in the order C0.C0.A0, C0.C0.A1, C0.C1.A0, … C1.C2.A1.
	private static SM9Fp12 Pattern(Func<int, SM9Fp> coefficient)
	{
		SM9Fp12 value = default;
		Span<SM9Fp> limbs = MemoryMarshal.Cast<SM9Fp12, SM9Fp>(new Span<SM9Fp12>(ref value));

		for (int i = 0; i < limbs.Length; ++i)
		{
			limbs[i] = coefficient(i);
		}

		return value;
	}

	// (3c² − 2c̄) + (3V·a² + 2b̄)·w + (3b² − 2ā)·w² over Fp4 = Fp2[V], V = w³, for c = (w⁰, w³), b = (w¹, w⁴) and a = (w², w⁵).
	private static Fp12Value CyclotomicSquare(Fp12Value f)
	{
		(Fp2Value c0, Fp2Value c1) = (f.C[0], f.C[3]);
		(Fp2Value b0, Fp2Value b1) = (f.C[1], f.C[4]);
		(Fp2Value a0, Fp2Value a1) = (f.C[2], f.C[5]);
		(Fp2Value cr, Fp2Value cv) = Square(c0, c1);
		(Fp2Value br, Fp2Value bv) = Square(b0, b1);
		(Fp2Value ar, Fp2Value av) = Square(a0, a1);
		return new Fp12Value([cr * 3 - c0 * 2, av * U * 3 + b0 * 2, br * 3 - a0 * 2, cv * 3 + c1 * 2, ar * 3 - b1 * 2, bv * 3 + a1 * 2]);

		// (x0 + x1·V)² = (x0² + u·x1²) + 2x0x1·V.
		static (Fp2Value Real, Fp2Value V) Square(Fp2Value x0, Fp2Value x1)
		{
			return (x0 * x0 + x1 * x1 * U, x0 * x1 * 2);
		}
	}

	private static void Check(List<string> failures, string operation, in SM9Fp2 actual, Fp2Value expected)
	{
		if (!IsReduced(actual) || ValueOf(actual) != expected)
		{
			failures.Add($"{operation} gave {ValueOf(actual)}, expected {expected}");
		}
	}

	private static void Check(List<string> failures, string operation, in SM9Fp12 actual, Fp12Value expected)
	{
		if (!IsReduced(actual) || ValueOf(actual) != expected)
		{
			failures.Add($"{operation} gave {ValueOf(actual)}, expected {expected}");
		}
	}
}
