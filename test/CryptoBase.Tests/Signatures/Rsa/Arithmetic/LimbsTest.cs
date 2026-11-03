using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

public class LimbsTest
{
	private static readonly int[] Lengths = [1, 2, 3, 4, 7, 16, 17, 33];

	[Test]
	public async Task BigEndianRoundTrips()
	{
		List<string> failures = [];
		Random random = new(11);

		for (int length = 0; length <= 41; ++length)
		{
			byte[] bytes = new byte[length];
			random.NextBytes(bytes);

			if (length > 2)
			{
				bytes[0] = 0;
			}

			ulong[] limbs = new ulong[(length + 7) / 8 + 1];
			Limbs.FromBigEndian(bytes, limbs);

			if (ToBigInteger(limbs) != FromBigEndian(bytes))
			{
				failures.Add($"FromBigEndian of {length} bytes");
			}

			byte[] written = new byte[length];
			Limbs.ToBigEndian(limbs, written);

			if (!written.AsSpan().SequenceEqual(bytes))
			{
				failures.Add($"ToBigEndian of {length} bytes");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task AdditionAndSubtractionMatchReference()
	{
		List<string> failures = [];
		Random random = new(12);

		foreach (int length in Lengths)
		{
			BigInteger word = BigInteger.One << 64 * length;

			foreach ((BigInteger x, BigInteger y) in Pairs(random, length))
			{
				ulong[] result = new ulong[length];
				ulong carry = Limbs.Add(ToLimbs(x, length), ToLimbs(y, length), result);

				if (ToBigInteger(result) + carry * word != x + y)
				{
					failures.Add($"{x:X} + {y:X}");
				}

				ulong borrow = Limbs.Subtract(ToLimbs(x, length), ToLimbs(y, length), result);

				if (ToBigInteger(result) - borrow * word != x - y)
				{
					failures.Add($"{x:X} − {y:X}");
				}

				ulong[] value = ToLimbs(x, length);
				carry = Limbs.AddInPlace(value, ToLimbs(y % (BigInteger.One << 64), 1));

				if (ToBigInteger(value) + carry * word != x + y % (BigInteger.One << 64))
				{
					failures.Add($"{x:X} += {y:X}");
				}

				value = ToLimbs(x, length);
				borrow = Limbs.SubtractSmall(value, (ulong)(y % (BigInteger.One << 64)));

				if (ToBigInteger(value) - borrow * word != x - y % (BigInteger.One << 64))
				{
					failures.Add($"{x:X} −= small {y:X}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ComparisonsMatchReference()
	{
		List<string> failures = [];
		Random random = new(13);

		foreach (int length in Lengths)
		{
			foreach ((BigInteger x, BigInteger y) in Pairs(random, length))
			{
				// One more limb on the right, which must not change the outcome.
				ulong[] left = ToLimbs(x, length);
				ulong[] right = ToLimbs(y, length + 1);

				if (Limbs.LessThan(left, right) != (x < y ? ulong.MaxValue : 0) || Limbs.LessThan(right, left) != (y < x ? ulong.MaxValue : 0))
				{
					failures.Add($"{x:X} < {y:X}");
				}

				if (Limbs.Equal(left, right) != (x == y ? ulong.MaxValue : 0) || Limbs.IsZero(left) != (x.IsZero ? ulong.MaxValue : 0))
				{
					failures.Add($"{x:X} = {y:X}");
				}

				if (Limbs.EqualSmall(left, 1) != (x.IsOne ? ulong.MaxValue : 0))
				{
					failures.Add($"{x:X} = 1");
				}

				ulong[] selected = new ulong[length];
				Limbs.Select(ulong.MaxValue, left, ToLimbs(y, length), selected);

				if (ToBigInteger(selected) != x)
				{
					failures.Add($"Select({x:X}, {y:X})");
				}

				Limbs.Select(0, left, ToLimbs(y, length), selected);

				if (ToBigInteger(selected) != y)
				{
					failures.Add($"Select({y:X}, {x:X})");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task MultiplicationMatchesReference()
	{
		List<string> failures = [];
		Random random = new(14);

		foreach (int length in Lengths)
		{
			foreach (int other in (ReadOnlySpan<int>)[1, length, length + 3])
			{
				foreach ((BigInteger x, BigInteger y) in Pairs(random, length))
				{
					BigInteger z = y % (BigInteger.One << 64 * other);
					ulong[] product = new ulong[length + other];
					Limbs.Multiply(ToLimbs(x, length), ToLimbs(z, other), product);

					if (ToBigInteger(product) != x * z)
					{
						failures.Add($"{x:X}·{z:X}");
					}
				}
			}

			BigInteger value = RandomBits(random, 64 * length);
			ulong small = (ulong)random.NextInt64() | 1;
			ulong addend = (ulong)random.NextInt64();
			ulong[] limbs = ToLimbs(value, length);
			ulong top = Limbs.MultiplySmall(limbs, small, addend);

			if (ToBigInteger(limbs) + (new BigInteger(top) << 64 * length) != value * small + addend)
			{
				failures.Add($"{value:X}·{small:X} + {addend:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task DivisionMatchesReference()
	{
		List<string> failures = [];
		Random random = new(15);

		foreach (int length in Lengths)
		{
			foreach (int dividendLength in (ReadOnlySpan<int>)[1, length, length + 1, 2 * length + 1])
			{
				foreach (BigInteger divisor in Moduli(random, length).Append(BigInteger.One << 64 * (length - 1) | 2))
				{
					foreach (BigInteger dividend in (ReadOnlySpan<BigInteger>)[BigInteger.Zero, divisor - 1, (BigInteger.One << 64 * dividendLength) - 1, RandomBits(random, 64 * dividendLength)])
					{
						if (dividend.GetBitLength() > 64 * dividendLength)
						{
							continue;
						}

						ulong[] remainder = new ulong[length];
						ulong[] scratch = new ulong[length];
						Limbs.Remainder(ToLimbs(dividend, dividendLength), ToLimbs(divisor, length), remainder, scratch);

						if (ToBigInteger(remainder) != dividend % divisor)
						{
							failures.Add($"{dividend:X} mod {divisor:X}");
						}

						ulong[] quotient = new ulong[dividendLength];
						Array.Clear(remainder);
						Limbs.Divide(ToLimbs(dividend, dividendLength), ToLimbs(divisor, length), quotient, remainder, scratch);

						if (ToBigInteger(quotient) != dividend / divisor || ToBigInteger(remainder) != dividend % divisor)
						{
							failures.Add($"{dividend:X} / {divisor:X}");
						}
					}
				}
			}

			// A divisor with zero top limbs, as the odd part of a gcd is.
			BigInteger small = RandomBits(random, 40) | 1;
			BigInteger value = RandomBits(random, 64 * length);
			ulong[] smallQuotient = new ulong[length];
			ulong[] smallRemainder = new ulong[length];
			Limbs.Divide(ToLimbs(value, length), ToLimbs(small, length), smallQuotient, smallRemainder, new ulong[length]);

			if (ToBigInteger(smallQuotient) != value / small || ToBigInteger(smallRemainder) != value % small)
			{
				failures.Add($"{value:X} / {small:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task GcdMatchesReference()
	{
		List<string> failures = [];
		Random random = new(16);

		foreach (int length in Lengths)
		{
			foreach ((BigInteger x, BigInteger y) in Pairs(random, length))
			{
				foreach ((BigInteger a, BigInteger b) in new[] { (x, y), (x << 3 | 8, y << 5 | 32), (x | 1, x | 1) })
				{
					BigInteger u = a % (BigInteger.One << 64 * length);
					BigInteger v = b % (BigInteger.One << 64 * length);

					if (u.IsZero && v.IsZero)
					{
						continue;
					}

					ulong[] odd = new ulong[length];
					int shift = Limbs.Gcd(ToLimbs(u, length), ToLimbs(v, length), odd, new ulong[2 * length]);

					if (ToBigInteger(odd) << shift != BigInteger.GreatestCommonDivisor(u, v) || ToBigInteger(odd).IsEven)
					{
						failures.Add($"gcd({u:X}, {v:X})");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ShiftsAndCountsMatchReference()
	{
		List<string> failures = [];
		Random random = new(17);

		foreach (int length in Lengths)
		{
			BigInteger value = RandomBits(random, 64 * length) | BigInteger.One << 64 * length - 1;

			for (int shift = 0; shift < 64 * length; shift += 1 + shift / 3)
			{
				ulong[] limbs = ToLimbs(value, length);
				Limbs.ShiftRight(limbs, shift);

				if (ToBigInteger(limbs) != value >> shift)
				{
					failures.Add($"{value:X} >> {shift}");
				}

				BigInteger shifted = (value << shift) % (BigInteger.One << 64 * length);
				int expected = shifted.IsZero ? 64 * length : (int)BigInteger.TrailingZeroCount(shifted);

				if (Limbs.TrailingZeroCount(ToLimbs(shifted, length)) != expected)
				{
					failures.Add($"tzcnt({shifted:X})");
				}

				if (Limbs.GetBitLength(ToLimbs(value >> shift, length)) != (int)(value >> shift).GetBitLength() || Limbs.GetLength(ToLimbs(value >> shift, length)) != ((int)(value >> shift).GetBitLength() + 63) / 64)
				{
					failures.Add($"length of {value >> shift:X}");
				}
			}

			if (Limbs.TrailingZeroCount(new ulong[length]) != 64 * length)
			{
				failures.Add($"tzcnt(0) of {length} limbs");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Every bit length that the limbs hold, from a single bit to all of them, below which the bits are clear, random or set; and zero.
	[Test]
	public async Task SecretBitLengthMatchesReference()
	{
		List<string> failures = [];
		Random random = new(18);

		foreach (int length in Lengths)
		{
			for (int bits = 0; bits <= 64 * length; ++bits)
			{
				BigInteger top = bits is 0 ? BigInteger.Zero : BigInteger.One << bits - 1;

				foreach (BigInteger value in (BigInteger[])[top, bits is 0 ? top : top | RandomBits(random, bits - 1), (BigInteger.One << bits) - 1])
				{
					if (Limbs.GetSecretBitLength(ToLimbs(value, length)) != bits)
					{
						failures.Add($"bit length of {value:X} in {length} limbs");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static IEnumerable<(BigInteger X, BigInteger Y)> Pairs(Random random, int length)
	{
		BigInteger max = (BigInteger.One << 64 * length) - 1;
		BigInteger x = RandomBits(random, 64 * length);
		BigInteger y = RandomBits(random, 64 * length);
		yield return (x, y);
		yield return (y, x);
		yield return (x, x);
		yield return (max, max);
		yield return (max, BigInteger.One);
		yield return (BigInteger.Zero, max);
		yield return (BigInteger.Zero, BigInteger.Zero);
		yield return (BigInteger.One, BigInteger.Zero);
	}
}
