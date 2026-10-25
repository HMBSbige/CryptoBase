using CryptoBase.EllipticCurves;

namespace CryptoBase.Tests.EllipticCurves;

// The inputs that need the most divsteps are out of reach of the inversion tests, so the constant-time batches are checked to cover the bound by construction.
public class SafeGcdTest
{
	[Test]
	public async Task BatchesCoverTheStepBound()
	{
		await Check<P256Field>(591);
		await Check<P256Order>(591);
		await Check<P384Field>(885);
		await Check<P384Order>(885);
		await Check<P521Field>(1201);
		await Check<P521Order>(1201);
	}

	private static async Task Check<TModulus>(int expectedBound) where TModulus : struct, IMontgomeryModulus
	{
		await Assert.That(SafeGcd<TModulus>.StepBound).IsEqualTo(expectedBound);
		await Assert.That(SafeGcd<TModulus>.BatchSteps).IsLessThanOrEqualTo(62);
		await Assert.That(SafeGcd<TModulus>.BatchCount * SafeGcd<TModulus>.BatchSteps).IsGreaterThanOrEqualTo(SafeGcd<TModulus>.StepBound);
	}
}
