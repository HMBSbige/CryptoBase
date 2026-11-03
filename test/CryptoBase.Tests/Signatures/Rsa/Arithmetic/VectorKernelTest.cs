using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// The vector kernels against the scalar kernel of the platform and BigInteger, in plain form after a round trip through Montgomery form: random products, and chains of products and squares in which each output feeds the next operation, as in an exponentiation, at the limb counts of MontgomeryKernelCase.LimbCountsToTest with the moduli of ModuliToTest.
public class VectorKernelTest
{
	private const int ChainLength = 64;

	public static IEnumerable<MontgomeryKernelCase> VectorKernels()
	{
		return MontgomeryKernelCase.All().Where(static kernel => MontgomeryKernelCase.IsVector(kernel.KernelType));
	}

	[Test]
	[MethodDataSource(nameof(VectorKernels))]
	public async Task ProductsMatchScalarKernel(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(11);

		foreach (int limbs in kernel.LimbCountsToTest)
		{
			foreach (BigInteger n in ModuliToTest(random, limbs))
			{
				ulong[] modulus = ToLimbs(n, limbs);
				using MontgomeryContext vector = kernel.Create(modulus);
				using MontgomeryContext scalar = CreateScalar(modulus);

				for (int trial = 0; trial < 16; ++trial)
				{
					BigInteger x = RandomBelow(random, n);
					BigInteger y = trial is 0 ? n - 1 : RandomBelow(random, n);
					BigInteger expected = x * y % n;
					BigInteger fromVector = Product(vector, x, y);
					BigInteger fromScalar = Product(scalar, x, y);

					if (fromVector != expected || fromScalar != expected)
					{
						failures.Add($"{n:X}: {x:X}·{y:X} gave {fromVector:X}, the scalar kernel {fromScalar:X}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(nameof(VectorKernels))]
	public async Task ChainsMatchScalarKernel(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(12);

		foreach (int limbs in kernel.LimbCountsToTest)
		{
			foreach (BigInteger n in ModuliToTest(random, limbs))
			{
				ulong[] modulus = ToLimbs(n, limbs);
				using MontgomeryContext vector = kernel.Create(modulus);
				using MontgomeryContext scalar = CreateScalar(modulus);
				BigInteger x = RandomBelow(random, n);
				BigInteger y = RandomBelow(random, n);
				BigInteger expected = x;

				for (int i = 0; i < ChainLength; ++i)
				{
					expected = (i & 1) is 0 ? expected * y % n : expected * expected % n;
				}

				BigInteger fromVector = Chain(vector, x, y);
				BigInteger fromScalar = Chain(scalar, x, y);

				if (fromVector != expected || fromScalar != expected)
				{
					failures.Add($"{n:X}: chain from {x:X} and {y:X} gave {fromVector:X}, the scalar kernel {fromScalar:X}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The scalar kernel that the dispatch would take without vectors: the largest digits that fit.
	private static MontgomeryContext CreateScalar(ReadOnlySpan<ulong> modulus)
	{
		int limbs = modulus.Length;
		return MontgomeryKernelCase.All().First(kernel => kernel.IsSupported && !MontgomeryKernelCase.IsVector(kernel.KernelType) && kernel.Fits(limbs)).Create(modulus);
	}

	private static BigInteger Product(MontgomeryContext context, BigInteger x, BigInteger y)
	{
		ulong[] left = new ulong[context.DigitCount];
		ulong[] right = new ulong[context.DigitCount];
		ulong[] result = new ulong[context.LimbCount];
		context.ToMontgomery(ToLimbs(x, context.LimbCount), left);
		context.ToMontgomery(ToLimbs(y, context.LimbCount), right);
		context.Multiply(left, left, right);
		context.FromMontgomery(left, result);
		return ToBigInteger(result);
	}

	// x·y, then its square, alternately, ChainLength times in all, in Montgomery form throughout.
	private static BigInteger Chain(MontgomeryContext context, BigInteger x, BigInteger y)
	{
		ulong[] value = new ulong[context.DigitCount];
		ulong[] factor = new ulong[context.DigitCount];
		ulong[] result = new ulong[context.LimbCount];
		context.ToMontgomery(ToLimbs(x, context.LimbCount), value);
		context.ToMontgomery(ToLimbs(y, context.LimbCount), factor);

		for (int i = 0; i < ChainLength; ++i)
		{
			if ((i & 1) is 0)
			{
				context.Multiply(value, value, factor);
			}
			else
			{
				context.Square(value, value);
			}
		}

		context.FromMontgomery(value, result);
		return ToBigInteger(result);
	}
}
