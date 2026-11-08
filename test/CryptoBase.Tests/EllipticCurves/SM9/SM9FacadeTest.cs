using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Vectors;

namespace CryptoBase.Tests.EllipticCurves.SM9;

// The entry points that the protocols take, against the reference and against each other: the constant-time products and the variable-time sums with the products by the generators, the pairing and its precomputed lines, and the powers with and without a table.
public class SM9FacadeTest
{
	[Test]
	public async Task G1ProductsAgree()
	{
		Random random = new(1);
		List<string> failures = [];
		G1Value point = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		SM9AffinePoint<SM9Fp> ePoint = Element(point);

		foreach (BigInteger k in SM9KernelTest.Scalars(random, 4))
		{
			FieldElement<SM9Order> scalar = Scalar(k);
			SM9G1.MultiplyBase(in scalar, out SM9AffinePoint<SM9Fp> baseProduct);
			SM9G1.Multiply(in ePoint, in scalar, out SM9AffinePoint<SM9Fp> product);
			bool sumFinite = SM9G1.MultiplyBaseAddVariableTime(in scalar, in ePoint, out SM9AffinePoint<SM9Fp> sum);
			G1Value? expectedSum = Add(Multiply(P1, k), point);

			if (ValueOf(baseProduct) != Multiply(P1, k) || ValueOf(product) != Multiply(point, k) || sumFinite != expectedSum is not null || expectedSum is not null && ValueOf(sum) != expectedSum)
			{
				failures.Add($"{k:X}");
			}
		}

		FieldElement<SM9Order> one = Scalar(1);
		SM9AffinePoint<SM9Fp> negated = Element(Negate(P1)!);
		bool infinite = !SM9G1.MultiplyBaseAddVariableTime(in one, in negated, out SM9AffinePoint<SM9Fp> zero);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(infinite).IsTrue();
			await Assert.That(RawValue(zero.X) | RawValue(zero.Y)).IsEqualTo(BigInteger.Zero);
		}
	}

	[Test]
	public async Task G2ProductsAgree()
	{
		Random random = new(2);
		List<string> failures = [];
		G2Value point = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		SM9AffinePoint<SM9Fp2> ePoint = Element(point);

		foreach (BigInteger k in SM9KernelTest.Scalars(random, 2).Take(12))
		{
			FieldElement<SM9Order> scalar = Scalar(k);
			SM9G2.MultiplyBase(in scalar, out SM9AffinePoint<SM9Fp2> baseProduct);
			bool sumFinite = SM9G2.MultiplyBaseAddVariableTime(in scalar, in ePoint, out SM9AffinePoint<SM9Fp2> sum);
			G2Value? expectedSum = Add(Multiply(P2, k), point);

			if (ValueOf(baseProduct) != Multiply(P2, k) || sumFinite != expectedSum is not null || expectedSum is not null && ValueOf(sum) != expectedSum)
			{
				failures.Add($"{k:X}");
			}
		}

		FieldElement<SM9Order> one = Scalar(1);
		SM9AffinePoint<SM9Fp2> negated = Element(Negate(P2)!);
		bool infinite = !SM9G2.MultiplyBaseAddVariableTime(in one, in negated, out SM9AffinePoint<SM9Fp2> zero);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(infinite).IsTrue();
			await Assert.That(RawValue(zero.X.A0) | RawValue(zero.X.A1) | RawValue(zero.Y.A0) | RawValue(zero.Y.A1)).IsEqualTo(BigInteger.Zero);
		}
	}

	[Test]
	public async Task PairingsAndPowersAgree()
	{
		SM9AffinePoint<SM9Fp> p1 = SM9G1.Generator;
		SM9AffinePoint<SM9Fp2> signPublic = Element(SM9PairingTest.SignPublic);
		SM9Pairing.Pair(in p1, in signPublic, out SM9Fp12 g);
		using SM9PairingLines lines = new(in signPublic);
		lines.PairVariableTime(in p1, out SM9Fp12 fromLines);
		using SM9GTTable table = new(in g);
		FieldElement<SM9Order> r = Scalar(Parse(SignR));
		FieldElement<SM9Order> h = Scalar(Parse(SignH));
		SM9GT.Power(in g, in r, out SM9Fp12 w);
		table.Power(in r, out SM9Fp12 wFromTable);
		SM9GT.Power(in g, in h, out SM9Fp12 t);
		table.Power(in h, out SM9Fp12 tFromTable);
		// The verification of GM/T 0044.5 A.2: u = e(S, P) and w' = u·t = w.
		SM9AffinePoint<SM9Fp> s = Element(SM9PairingTest.Signature);
		SM9AffinePoint<SM9Fp2> verifyP = Element(SM9PairingTest.VerifyP);
		SM9Pairing.Pair(in s, in verifyP, out SM9Fp12 u);
		SM9Fp12.Multiply(in u, in t, out SM9Fp12 wVerified);
		byte[] encoded = new byte[SM9GT.EncodedLength];
		SM9GT.Encode(in g, encoded);

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(encoded)).IsEqualTo(SignG);
			await Assert.That(SM9GT.AreEqual(in g, in fromLines)).IsEqualTo(ulong.MaxValue);
			await Assert.That(ValueOf(w).ToHex()).IsEqualTo(SignW);
			await Assert.That(SM9GT.AreEqual(in w, in wFromTable)).IsEqualTo(ulong.MaxValue);
			await Assert.That(ValueOf(t).ToHex()).IsEqualTo(VerifyT);
			await Assert.That(SM9GT.AreEqual(in t, in tFromTable)).IsEqualTo(ulong.MaxValue);
			await Assert.That(ValueOf(u).ToHex()).IsEqualTo(VerifyU);
			await Assert.That(SM9GT.AreEqual(in wVerified, in w)).IsEqualTo(ulong.MaxValue);
			await Assert.That(SM9GT.AreEqual(in w, in t)).IsEqualTo(0UL);
		}
	}

	// The pairings of public points in projective form with random Z against the products of the constant-time pairings of their affine forms, with the point at infinity as P′, whose pairing is 1, and the verification of GM/T 0044.5 A.2 from the projective products of SM9G1, w′ = e([h1]S, P2)·e(S + [h]P1, Ppub-s) = w.
	[Test]
	public async Task ProjectivePairingsMatchTheAffineOnes()
	{
		Random random = new(4);
		List<string> failures = [];
		SM9AffinePoint<SM9Fp2> q = Element(Multiply(P2, RandomBelow(random, N - 1) + 1)!);
		SM9AffinePoint<SM9Fp2> otherQ = Element(Multiply(P2, RandomBelow(random, N - 1) + 1)!);
		using SM9PairingLines lines = new(in q);
		using SM9PairingLines otherLines = new(in otherQ);

		for (int i = 0; i < 3; ++i)
		{
			G1Value p = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
			G1Value other = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
			SM9Pairing.Pair(Element(p), in q, out SM9Fp12 first);
			SM9Pairing.Pair(Element(other), in otherQ, out SM9Fp12 second);
			SM9Fp12.Multiply(in first, in second, out SM9Fp12 expected);
			lines.PairVariableTime(Projective(p, RandomBelow(random, P - 1) + 1), otherLines, Projective(other, RandomBelow(random, P - 1) + 1), out SM9Fp12 product);
			lines.PairVariableTime(Projective(p, RandomBelow(random, P - 1) + 1), otherLines, Projective(null, RandomBelow(random, P - 1) + 1), out SM9Fp12 single);
			lines.PairVariableTime(Element(p), out SM9Fp12 affine);

			if (SM9GT.AreEqual(in product, in expected) is 0 || SM9GT.AreEqual(in single, in first) is 0 || SM9GT.AreEqual(in affine, in first) is 0)
			{
				failures.Add($"pair {i}");
			}
		}

		SM9AffinePoint<SM9Fp> s = Element(SM9PairingTest.Signature);
		SM9AffinePoint<SM9Fp2> signPublic = Element(SM9PairingTest.SignPublic);
		using SM9PairingLines publicLines = new(in signPublic);
		SM9G1.MultiplyVariableTime(in s, Scalar(Parse(VerifyH1)), out SM9Point<SM9Fp> scaled);
		SM9G1.MultiplyBaseAddVariableTime(Scalar(Parse(SignH)), in s, out SM9Point<SM9Fp> shifted);
		SM9PairingLines.Generator.PairVariableTime(in scaled, publicLines, in shifted, out SM9Fp12 w);
		FieldElement<SM9Order> one = Scalar(1);
		SM9AffinePoint<SM9Fp> negated = Element(Negate(P1)!);
		SM9G1.MultiplyBaseAddVariableTime(in one, in negated, out SM9Point<SM9Fp> zero);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(ValueOf(w).ToHex()).IsEqualTo(SignW);
			await Assert.That(ValueOf(scaled)).IsEqualTo(Multiply(SM9PairingTest.Signature, Parse(VerifyH1)));
			await Assert.That(ValueOf(shifted)).IsEqualTo(Add(SM9PairingTest.Signature, Multiply(P1, Parse(SignH))));
			await Assert.That(ValueOf(zero)).IsNull();
		}
	}

	[Test]
	public async Task DisposeErasesTheTables()
	{
		SM9AffinePoint<SM9Fp2> key = Element(SM9PairingTest.EncryptKey);
		SM9PairingLines lines = new(in key);
		lines.Dispose();
		SM9PrecomputedLine[] stored = (SM9PrecomputedLine[])typeof(SM9PairingLines).GetField("_lines", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(lines)!;
		await Assert.That(stored.All(static line => RawValue(line.A.A0).IsZero && RawValue(line.A.A1).IsZero && RawValue(line.B.A0).IsZero && RawValue(line.B.A1).IsZero)).IsTrue();
	}
}
