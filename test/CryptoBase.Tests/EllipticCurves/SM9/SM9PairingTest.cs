using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Vectors;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public class SM9PairingTest
{
	internal static readonly G2Value SignPublic = G2(SignPublicX1, SignPublicX0, SignPublicY1, SignPublicY0);

	internal static readonly G1Value Signature = G1(SignatureX, SignatureY);

	internal static readonly G2Value VerifyP = G2(VerifyPX1, VerifyPX0, VerifyPY1, VerifyPY0);

	internal static readonly G2Value ExchangeKeyA = G2(ExchangeKeyAX1, ExchangeKeyAX0, ExchangeKeyAY1, ExchangeKeyAY0);

	internal static readonly G2Value ExchangeKeyB = G2(ExchangeKeyBX1, ExchangeKeyBX0, ExchangeKeyBY1, ExchangeKeyBY0);

	internal static readonly G1Value ExchangePointA = G1(ExchangePointAX, ExchangePointAY);

	internal static readonly G1Value ExchangePointB = G1(ExchangePointBX, ExchangePointBY);

	private static readonly G1Value EncryptPublic = G1(EncryptPublicX, EncryptPublicY);

	internal static readonly G2Value EncryptKey = G2(EncryptKeyX1, EncryptKeyX0, EncryptKeyY1, EncryptKeyY0);

	internal static readonly G1Value EncapsulateC = G1(EncapsulateCX, EncapsulateCY);

	internal static readonly G1Value EncryptC1 = G1(EncryptC1X, EncryptC1Y);

	// The pairing values of the examples: e(P1, Ppub-s), e(S, P) of the verification, e(RA, deB) and e(RB, deA) of the key exchange, e(Ppub-e, P2) of the encapsulation and e(C, deB) of the decapsulation and decryption.
	public static IEnumerable<Func<(G1Value P, G2Value Q, string Expected)>> Examples()
	{
		yield return () => (P1, SignPublic, SignG);
		yield return () => (Signature, VerifyP, VerifyU);
		yield return () => (ExchangePointA, ExchangeKeyB, ExchangeG1);
		yield return () => (ExchangePointB, ExchangeKeyA, ExchangeG2);
		yield return () => (EncryptPublic, P2, EncryptG);
		yield return () => (EncapsulateC, EncryptKey, EncapsulateW);
		yield return () => (EncryptC1, EncryptKey, EncryptW);
	}

	// The reference follows GM/T 0044.1 B.6.2 literally, so it checks the reading of the standard behind both it and the implementation.
	[Test]
	public async Task ReferenceGivesTheSignatureExample()
	{
		await Assert.That(Pairing(P1, SignPublic).ToHex()).IsEqualTo(SignG);
	}

	[Test]
	[MethodDataSource(nameof(Examples))]
	public async Task PairingGivesTheExamples(G1Value p, G2Value q, string expected)
	{
		SM9AffinePoint<SM9Fp> ep = Element(p);
		SM9AffinePoint<SM9Fp2> eq = Element(q);
		SM9MillerLoop.Run(in ep, in eq, out SM9Fp12 f);
		SM9FinalExponentiation.Run(in f, out SM9Fp12 direct);
		SM9PrecomputedLine[] lines = new SM9PrecomputedLine[SM9MillerLoop.LineCount];
		SM9MillerLoop.Precompute(in eq, lines);
		SM9MillerLoop.FactorsVariableTime(in ep, out SM9Fp alpha, out SM9Fp beta);
		SM9MillerLoop.Run(in alpha, in beta, lines, out SM9Fp12 g);
		SM9FinalExponentiation.Run(in g, out SM9Fp12 precomputed);

		using (Assert.Multiple())
		{
			await Assert.That(ValueOf(direct).ToHex()).IsEqualTo(expected);
			await Assert.That(ValueOf(precomputed).ToHex()).IsEqualTo(expected);
			await Assert.That(IsReduced(direct)).IsTrue();
		}
	}

	// The chain of the hard part against the plain power (p¹² − 1)/N.
	[Test]
	public async Task FinalExponentiationIsThePower()
	{
		Random random = new(1);
		BigInteger exponent = (BigInteger.Pow(P, 12) - 1) / N;
		List<string> failures = [];

		for (int i = 0; i < 2; ++i)
		{
			Fp12Value f = RandomFp12(random);
			SM9Fp12 element = Element(f);
			SM9FinalExponentiation.Run(in element, out SM9Fp12 result);
			SM9Fp12 expected = Element(Fp12Value.One);

			for (int bit = (int)exponent.GetBitLength() - 1; bit >= 0; --bit)
			{
				SM9Fp12.Square(in expected, out expected);

				if (!(exponent >> bit & 1).IsZero)
				{
					SM9Fp12.Multiply(in expected, in element, out expected);
				}
			}

			if (ValueOf(result) != ValueOf(expected))
			{
				failures.Add($"{f}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
