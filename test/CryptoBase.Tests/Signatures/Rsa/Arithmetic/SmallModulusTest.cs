using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

public class SmallModulusTest
{
	// The usual public exponents, composite ones, and the largest odd moduli that the methods take.
	private static readonly ulong[] Moduli = [3, 5, 17, 65537, 255255, 4294967297, (1UL << 33) - 1, (1UL << 33) + 1, (1UL << 34) - 1, (1UL << 34) - 3];

	[Test]
	public async Task RemainderMatchesReference()
	{
		List<string> failures = [];
		Random random = new(21);

		foreach (ulong modulus in Moduli.Append((ulong)random.NextInt64() & (1UL << 34) - 1 | 1))
		{
			foreach (int length in (ReadOnlySpan<int>)[1, 2, 5, 16, 32, 257])
			{
				foreach (BigInteger value in (ReadOnlySpan<BigInteger>)[BigInteger.Zero, (BigInteger.One << 64 * length) - 1, RandomBits(random, 64 * length), modulus * RandomBits(random, 64 * length - 35)])
				{
					if (SmallModulus.Remainder(ToLimbs(value, length), modulus) != value % modulus)
					{
						failures.Add($"{value:X} mod {modulus}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task GcdAndInverseMatchReference()
	{
		List<string> failures = [];
		Random random = new(22);

		foreach (ulong modulus in Moduli)
		{
			foreach (ulong x in (ReadOnlySpan<ulong>)[0, 1, 2, modulus - 1, modulus - 2, (ulong)random.NextInt64() % modulus, modulus / 3 * 3 % modulus, modulus / 5 * 5 % modulus])
			{
				bool coprime = BigInteger.GreatestCommonDivisor(x, modulus).IsOne;

				if (SmallModulus.IsCoprime(x, modulus) != (coprime ? ulong.MaxValue : 0))
				{
					failures.Add($"gcd({x}, {modulus})");
				}

				if (coprime && SmallModulus.Inverse(x, modulus) != ModInverse(x, modulus))
				{
					failures.Add($"{x}⁻¹ mod {modulus}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task DivideExactMatchesReference()
	{
		List<string> failures = [];
		Random random = new(23);

		foreach (ulong divisor in Moduli)
		{
			foreach (int length in (ReadOnlySpan<int>)[1, 2, 17, 33])
			{
				BigInteger quotient = RandomBits(random, 64 * length - 35);
				ulong[] value = ToLimbs(quotient * divisor, length);
				SmallModulus.DivideExact(value, divisor);

				if (ToBigInteger(value) != quotient)
				{
					failures.Add($"{quotient:X}·{divisor} / {divisor}");
				}

				ulong[] all = ToLimbs((BigInteger.One << 64 * length) - 1 - ((BigInteger.One << 64 * length) - 1) % divisor, length);
				BigInteger expected = ToBigInteger(all) / divisor;
				SmallModulus.DivideExact(all, divisor);

				if (ToBigInteger(all) != expected)
				{
					failures.Add($"largest multiple of {divisor} in {length} limbs");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
