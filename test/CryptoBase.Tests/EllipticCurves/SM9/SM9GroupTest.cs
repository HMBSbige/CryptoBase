using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public class SM9GroupTest
{
	private static readonly BigInteger Lambda = Parse("1E600000005474DE26804E46A9A65C91E2BF5F68BCD8990E5");

	private static readonly BigInteger Trace = 6 * T * T + 1;

	// Pairs of points of G1 with the special cases of the complete formulas: equal, opposite and at infinity.
	private static IEnumerable<(G1Value? Left, G1Value? Right)> G1Pairs(Random random)
	{
		G1Value a = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		G1Value b = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		return [(a, b), (a, a), (a, Negate(a)), (a, null), (null, a), (null, null), (P1, P1), (Multiply(P1, N - 1), P1)];
	}

	private static IEnumerable<(G2Value? Left, G2Value? Right)> G2Pairs(Random random)
	{
		G2Value a = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		G2Value b = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		// A point of the twist outside G2, which the formulas take as well.
		G2Value c = RandomTwistPoint(random);
		return [(a, b), (a, a), (a, Negate(a)), (a, null), (null, a), (null, null), (c, a), (c, c), (c, Negate(c))];
	}

	[Test]
	public async Task G1FormulasAreComplete()
	{
		Random random = new(1);
		List<string> failures = [];

		foreach ((G1Value? left, G1Value? right) in G1Pairs(random))
		{
			SM9Point<SM9Fp> l = Projective(left, RandomBelow(random, P - 1) + 1);
			SM9Point<SM9Fp> r = Projective(right, RandomBelow(random, P - 1) + 1);
			SM9Curve<SM9Fp>.Add(in l, in r, out SM9Point<SM9Fp> sum);
			SM9Curve<SM9Fp>.Double(in l, out SM9Point<SM9Fp> twice);
			G1Value? expected = Add(left, right);

			if (ValueOf(sum) != expected || ValueOf(twice) != Add(left, left))
			{
				failures.Add($"Add or Double {left}, {right}");
			}

			if (right is not null)
			{
				SM9AffinePoint<SM9Fp> affine = Element(right);
				SM9Curve<SM9Fp>.Add(in l, in affine, out SM9Point<SM9Fp> mixed);

				if (ValueOf(mixed) != expected)
				{
					failures.Add($"mixed Add {left}, {right}");
				}
			}

			if (SM9Curve<SM9Fp>.AreEqual(in l, in r) is not 0 != (left == right))
			{
				failures.Add($"AreEqual {left}, {right}");
			}

			// Results may be inputs.
			SM9Curve<SM9Fp>.Add(in l, in r, out l);

			if (ValueOf(l) != expected)
			{
				failures.Add($"aliased Add {left}, {right}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task G2FormulasAreComplete()
	{
		Random random = new(2);
		List<string> failures = [];

		foreach ((G2Value? left, G2Value? right) in G2Pairs(random))
		{
			SM9Point<SM9Fp2> l = Projective(left, RandomFp2(random));
			SM9Point<SM9Fp2> r = Projective(right, RandomFp2(random));
			SM9Curve<SM9Fp2>.Add(in l, in r, out SM9Point<SM9Fp2> sum);
			SM9Curve<SM9Fp2>.Double(in l, out SM9Point<SM9Fp2> twice);
			G2Value? expected = Add(left, right);

			if (ValueOf(sum) != expected || ValueOf(twice) != Add(left, left))
			{
				failures.Add($"Add or Double {left}, {right}");
			}

			if (right is not null)
			{
				SM9AffinePoint<SM9Fp2> affine = Element(right);
				SM9Curve<SM9Fp2>.Add(in l, in affine, out SM9Point<SM9Fp2> mixed);

				if (ValueOf(mixed) != expected)
				{
					failures.Add($"mixed Add {left}, {right}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task AffineFormsMatchTheProjectiveOnes()
	{
		Random random = new(3);
		SM9Point<SM9Fp>[] points = new SM9Point<SM9Fp>[5];
		G1Value[] values = new G1Value[points.Length];

		for (int i = 0; i < points.Length; ++i)
		{
			values[i] = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
			points[i] = Projective(values[i], RandomBelow(random, P - 1) + 1);
		}

		SM9AffinePoint<SM9Fp>[] batch = new SM9AffinePoint<SM9Fp>[points.Length];
		SM9AffinePoint<SM9Fp>[] batchVariableTime = new SM9AffinePoint<SM9Fp>[points.Length];
		SM9Curve<SM9Fp>.ToAffine(points, batch, false);
		SM9Curve<SM9Fp>.ToAffine(points, batchVariableTime, true);
		ulong infinity = SM9Curve<SM9Fp>.ToAffine(in points[0], out SM9AffinePoint<SM9Fp> single);
		SM9Point<SM9Fp> atInfinity = Projective(null, 5);
		ulong isInfinity = SM9Curve<SM9Fp>.ToAffine(in atInfinity, out SM9AffinePoint<SM9Fp> zero);
		bool finite = SM9Curve<SM9Fp>.ToAffineVariableTime(in atInfinity, out _);

		using (Assert.Multiple())
		{
			await Assert.That(batch.Select(static point => ValueOf(point))).IsEquivalentTo(values, CollectionOrdering.Matching);
			await Assert.That(batchVariableTime.Select(static point => ValueOf(point))).IsEquivalentTo(values, CollectionOrdering.Matching);
			await Assert.That(ValueOf(single)).IsEqualTo(values[0]);
			await Assert.That(infinity).IsEqualTo(0UL);
			await Assert.That(isInfinity).IsEqualTo(ulong.MaxValue);
			await Assert.That(RawValue(zero.X) | RawValue(zero.Y)).IsEqualTo(BigInteger.Zero);
			await Assert.That(finite).IsFalse();
		}
	}

	[Test]
	public async Task G1EncodingsRoundTripAndRejectBadPoints()
	{
		byte[] encoded = new byte[SM9G1.EncodedLength];
		SM9G1.Encode(in SM9G1.Generator, encoded);
		bool valid = SM9G1.TryDecode(encoded, out SM9AffinePoint<SM9Fp> decoded);
		List<string> rejected = [];

		foreach ((string name, byte[] bad) in BadG1Encodings(encoded))
		{
			if (SM9G1.TryDecode(bad, out SM9AffinePoint<SM9Fp> result) || RawValue(result.X) != 0 || RawValue(result.Y) != 0)
			{
				rejected.Add(name);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(encoded)).IsEqualTo("04" + Hex(P1.X) + Hex(P1.Y));
			await Assert.That(valid).IsTrue();
			await Assert.That(ValueOf(decoded)).IsEqualTo(P1);
			await Assert.That(rejected).IsEmpty();
		}
	}

	[Test]
	public async Task G2EncodingsRoundTripAndRejectBadPoints()
	{
		Random random = new(4);
		byte[] encoded = new byte[SM9G2.EncodedLength];
		SM9G2.Encode(in SM9G2.Generator, encoded);
		bool valid = SM9G2.TryDecode(encoded, out SM9AffinePoint<SM9Fp2> decoded);
		G2Value outside = RandomTwistPoint(random);
		G2Value cofactorPoint = Multiply(outside, N)!;
		List<string> rejected = [];
		List<(string Name, byte[] Encoding)> bad =
		[
			("short", encoded[..^1]),
			("long", [.. encoded, 0]),
			("compressed", [0x02, .. encoded[1..65]]),
			("x0 = p", [0x04, .. Encode(P2.X.A1), .. Encode(P), .. encoded[65..]]),
			("x1 = p", [0x04, .. Encode(P), .. encoded[33..]]),
			("y off the twist", Encode2(P2 with { Y = P2.Y + Fp2Value.One })),
			("outside G2", Encode2(outside)),
			("in the cofactor group", Encode2(cofactorPoint)),
			("plus a point outside G2", Encode2(Add(P2, outside)!)),
		];

		foreach ((string name, byte[] encoding) in bad)
		{
			if (SM9G2.TryDecode(encoding, out SM9AffinePoint<SM9Fp2> result) || !ValueOf(result).X.IsZero || !ValueOf(result).Y.IsZero)
			{
				rejected.Add(name);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(encoded)).IsEqualTo("04" + Hex(P2.X.A1) + Hex(P2.X.A0) + Hex(P2.Y.A1) + Hex(P2.Y.A0));
			await Assert.That(valid).IsTrue();
			await Assert.That(ValueOf(decoded)).IsEqualTo(P2);
			await Assert.That(rejected).IsEmpty();
			await Assert.That(IsOnTwist(outside) && IsOnTwist(cofactorPoint)).IsTrue();
		}
	}

	// The subgroup check of SM9G2.TryDecode, SM9G2Group.IsInSubgroupVariableTime: α = (6t + 2) + ψ − ψ² + ψ³ reduced by ψ² = tr·ψ − p to α0 + α1·ψ has the norm n = α0² + α0·α1·tr + α1²·p, which N divides and which is prime to the cofactor 2p − N, and α acts as 0 on G2.
	[Test]
	public async Task SubgroupCheckIsExact()
	{
		BigInteger[] alpha = [6 * T + 2, 1, -1, 1];

		for (int i = alpha.Length - 1; i >= 2; --i)
		{
			alpha[i - 1] += alpha[i] * Trace;
			alpha[i - 2] -= alpha[i] * P;
			alpha[i] = 0;
		}

		BigInteger norm = alpha[0] * alpha[0] + alpha[0] * alpha[1] * Trace + alpha[1] * alpha[1] * P;
		BigInteger eigenvalue = (6 * T + 2 + P - P * P + P * P * P) % N;
		Random random = new(5);
		List<string> failures = [];
		List<G2Value> members = [P2, SM9PairingTest.SignPublic, SM9PairingTest.ExchangeKeyA, SM9PairingTest.ExchangeKeyB, SM9PairingTest.EncryptKey, Multiply(P2, N - 1)!];

		foreach (G2Value member in members)
		{
			if (!SM9G2.TryDecode(Encode2(member), out _))
			{
				failures.Add($"member {member}");
			}
		}

		for (int i = 0; i < 4; ++i)
		{
			G2Value outside = RandomTwistPoint(random);

			if (SM9G2.TryDecode(Encode2(outside), out _) || Multiply(outside, N) is null)
			{
				failures.Add($"outside {outside}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(eigenvalue).IsEqualTo(BigInteger.Zero);
			await Assert.That(norm % N).IsEqualTo(BigInteger.Zero);
			await Assert.That(BigInteger.GreatestCommonDivisor(norm, TwistCofactor)).IsEqualTo(BigInteger.One);
			await Assert.That(BigInteger.GreatestCommonDivisor(N, TwistCofactor)).IsEqualTo(BigInteger.One);
		}
	}

	// φ(P) = [λ]P on G1 and ψ(Q) = [p]Q on G2, the eigenvalues of the decompositions.
	[Test]
	public async Task EndomorphismsActAsTheirEigenvalues()
	{
		Random random = new(6);
		G1Value p = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		G2Value q = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		SM9Point<SM9Fp> ep = Projective(p, 9);
		SM9G1Group.Endomorphism(in ep, out SM9Point<SM9Fp> phi);
		SM9AffinePoint<SM9Fp2> eq = Element(q);
		SM9G2Group.Frobenius(in eq, out SM9AffinePoint<SM9Fp2> psi);
		SM9Point<SM9Fp2> projective = Projective(q, new Fp2Value(4, 7));
		SM9G2Group.Frobenius(in projective, out SM9Point<SM9Fp2> psiProjective);
		SM9G2Group.NegatedFrobeniusSquared(in eq, out SM9AffinePoint<SM9Fp2> psi2);

		using (Assert.Multiple())
		{
			await Assert.That(ModN(Lambda * Lambda + Lambda + 1)).IsEqualTo(BigInteger.Zero);
			await Assert.That(ValueOf(phi)).IsEqualTo(Multiply(p, Lambda));
			await Assert.That(ValueOf(psi)).IsEqualTo(Multiply(q, P % N));
			await Assert.That(ValueOf(psi)).IsEqualTo(Frobenius(q));
			await Assert.That(ValueOf(psiProjective)).IsEqualTo(Multiply(q, P % N));
			await Assert.That(ValueOf(psi2)).IsEqualTo(Negate(Multiply(q, P * P % N)));
		}
	}

	[Test]
	public async Task DecompositionsAreShortAndExact()
	{
		Random random = new(7);
		// The basis of G1 and the bounds of its parts, (1/2 + 2^−65)·(b + c) and (1/2 + 2^−65)·(a + b), in units of 2^−65.
		BigInteger a = 6 * T * T + 2 * T;
		BigInteger b = 2 * T + 1;
		BigInteger c = 6 * T * T + 4 * T + 1;
		BigInteger bound1 = ((BigInteger.One << 64) + 1) * (b + c);
		BigInteger bound2 = ((BigInteger.One << 64) + 1) * (a + b);
		List<string> failures = [];
		// The fixed scalars that the tests of the products and powers take give both an odd and an even k0, so both sides of the correction run.
		HashSet<bool> parities = [];

		foreach (BigInteger k in SM9KernelTest.Scalars(random, 0))
		{
			FieldElement<SM9Order> scalar = Scalar(k);
			SM9Decomposition.DecomposeFrobenius(in scalar, out UInt128 f0, out _, out _, out _);
			parities.Add((f0 & 1) == 1);
		}

		if (parities.Count is not 2)
		{
			failures.Add("parities of k0");
		}

		foreach (BigInteger k in (List<BigInteger>)[0, .. SM9KernelTest.Scalars(random, 200)])
		{
			FieldElement<SM9Order> scalar = Scalar(k);
			SM9Decomposition.DecomposeG1(in scalar, out UInt128 k1, out UInt128 k2);
			BigInteger s1 = (Int128)k1;
			BigInteger s2 = (Int128)k2;
			// The parts must be those of some β0 and β1 within 1/2 + 2^−65 of k·a/N and k·b/N, computed before their reduction to 128 bits, and within the bounds.
			bool exact = false;

			foreach (BigInteger beta0 in Roundings(k * a))
			{
				foreach (BigInteger beta1 in Roundings(k * b))
				{
					BigInteger e1 = k - beta0 * c - beta1 * b;
					BigInteger e2 = beta1 * a - beta0 * b;
					exact |= e1 == s1 && e2 == s2 && BigInteger.Abs(e1) << 65 <= bound1 && BigInteger.Abs(e2) << 65 <= bound2;
				}
			}

			if (ModN(s1 + s2 * Lambda) != k || !exact)
			{
				failures.Add($"DecomposeG1 {k:X}");
			}

			SM9Decomposition.DecomposeFrobenius(in scalar, out UInt128 f0, out UInt128 f1, out UInt128 f2, out UInt128 f3);
			BigInteger[] parts = [f0, f1, f2, f3];

			if (ModN(parts[0] + parts[1] * P + parts[2] * P * P + parts[3] * P * P * P) != k || parts[0] >= BigInteger.One << 67 || parts.Skip(1).Any(static part => part >= BigInteger.One << 66))
			{
				failures.Add($"DecomposeFrobenius {k:X}");
			}

			// The digits give back each part.
			byte[] digits = new byte[SM9FrobeniusRecoding.Length];
			UInt128 odd = f0 | 1;
			SM9FrobeniusRecoding.Recode(odd, f1, f2, f3, digits);
			BigInteger[] recoded = new BigInteger[4];

			for (int i = digits.Length - 1; i >= 0; --i)
			{
				// Bit 3 of a position is the negative sign.
				int sign = (digits[i] >> 3 & 1) is 0 ? 1 : -1;

				for (int j = 0; j < 4; ++j)
				{
					recoded[j] = 2 * recoded[j] + (j is 0 ? sign : sign * (digits[i] >> j - 1 & 1));
				}
			}

			if (recoded[0] != odd || recoded[1] != f1 || recoded[2] != f2 || recoded[3] != f3)
			{
				failures.Add($"Recode {k:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The integers within 1/2 + 2^−65 of numerator/N, for a numerator of at least 0: the nearest, and the other neighbor too where the quotient lies that close to a half.
	private static IEnumerable<BigInteger> Roundings(BigInteger numerator)
	{
		BigInteger floor = BigInteger.DivRem(numerator, N, out BigInteger remainder);
		BigInteger tolerance = ((BigInteger.One << 64) + 1) * N;

		if (remainder << 65 <= tolerance)
		{
			yield return floor;
		}

		if (N - remainder << 65 <= tolerance)
		{
			yield return floor + 1;
		}
	}

	private static G2Value RandomTwistPoint(Random random)
	{
		while (true)
		{
			if (TwistPoint(RandomFp2(random)) is { } point)
			{
				return point;
			}
		}
	}

	private static byte[] Encode2(G2Value point)
	{
		return [0x04, .. Encode(point.X.A1), .. Encode(point.X.A0), .. Encode(point.Y.A1), .. Encode(point.Y.A0)];
	}

	private static IEnumerable<(string Name, byte[] Encoding)> BadG1Encodings(byte[] encoded)
	{
		yield return ("short", encoded[..^1]);
		yield return ("long", [.. encoded, 0]);
		yield return ("infinity", [0x00]);
		yield return ("compressed", [0x02, .. encoded[1..33]]);
		yield return ("hybrid", [0x06, .. encoded[1..]]);
		yield return ("x = p", [0x04, .. Encode(P), .. encoded[33..]]);
		yield return ("y = p", [.. encoded[..33], .. Encode(P)]);
		yield return ("off the curve", [.. encoded[..33], .. Encode(Mod(P1.Y + 1))]);
	}
}
