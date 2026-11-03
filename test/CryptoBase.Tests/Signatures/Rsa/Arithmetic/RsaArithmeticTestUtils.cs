using System.Numerics;
using System.Reflection;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

public static class RsaArithmeticTestUtils
{
	// Limb counts of the CRT halves and moduli of RSA-1024 to RSA-16384, odd counts, and the counts around them.
	public static readonly int[] LimbCounts = [1, 2, 3, 5, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 47, 48, 63, 64, 65, 96, 127, 128, 129, 192, 255, 256];

	public static BigInteger ToBigInteger(ReadOnlySpan<ulong> limbs, int bitsPerLimb = 64)
	{
		BigInteger value = BigInteger.Zero;

		for (int i = limbs.Length - 1; i >= 0; --i)
		{
			value = (value << bitsPerLimb) + limbs[i];
		}

		return value;
	}

	public static ulong[] ToLimbs(BigInteger value, int count, int bitsPerLimb = 64)
	{
		ulong[] limbs = new ulong[count];
		BigInteger mask = (BigInteger.One << bitsPerLimb) - 1;

		for (int i = 0; i < count; ++i)
		{
			limbs[i] = (ulong)(value & mask);
			value >>= bitsPerLimb;
		}

		if (!value.IsZero)
		{
			throw new ArgumentOutOfRangeException(nameof(value), "The value does not fit.");
		}

		return limbs;
	}

	public static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		int bytes = (int)((bound.GetBitLength() + 7) / 8) + 8;
		byte[] buffer = new byte[bytes];
		random.NextBytes(buffer);
		return new BigInteger(buffer, true) % bound;
	}

	public static BigInteger RandomBits(Random random, int bits)
	{
		byte[] buffer = new byte[(bits + 7) / 8];
		random.NextBytes(buffer);
		return new BigInteger(buffer, true) & (BigInteger.One << bits) - 1;
	}

	// Odd moduli of limbs limbs with a nonzero top limb, in shapes that stress the reduction: random, a top limb of 1, all ones, the smallest with the top bit set, and just below a power of two that is not a multiple of 64.
	public static IEnumerable<BigInteger> Moduli(Random random, int limbs)
	{
		int bits = 64 * limbs;
		BigInteger low = BigInteger.One << 64 * (limbs - 1);
		yield return RandomBits(random, bits) | BigInteger.One << bits - 1 | 1;
		yield return limbs is 1 ? 3 : low + (RandomBits(random, 64 * (limbs - 1)) | 1);
		yield return (BigInteger.One << bits) - 1;
		yield return (BigInteger.One << bits - 1) + 1;
		yield return BigInteger.Max(low + 1, (BigInteger.One << bits - 7) - 1) | 1;
	}

	public static BigInteger ModInverse(BigInteger value, BigInteger modulus)
	{
		BigInteger oldR = (value % modulus + modulus) % modulus;
		BigInteger r = modulus;
		BigInteger oldS = BigInteger.One;
		BigInteger s = BigInteger.Zero;

		while (!r.IsZero)
		{
			BigInteger quotient = oldR / r;
			(oldR, r) = (r, oldR - quotient * r);
			(oldS, s) = (s, oldS - quotient * s);
		}

		if (!oldR.IsOne)
		{
			throw new ArgumentException("The value has no inverse.", nameof(value));
		}

		return (oldS % modulus + modulus) % modulus;
	}

	public static bool IsProbablePrime(BigInteger value, Random random, int rounds = 40)
	{
		if (value < 2)
		{
			return false;
		}

		foreach (int prime in (ReadOnlySpan<int>)[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37])
		{
			if (value == prime)
			{
				return true;
			}

			if ((value % prime).IsZero)
			{
				return false;
			}
		}

		BigInteger m = value - 1;
		int a = 0;

		while (m.IsEven)
		{
			m >>= 1;
			++a;
		}

		for (int i = 0; i < rounds; ++i)
		{
			BigInteger b = 2 + RandomBelow(random, value - 3);
			BigInteger z = BigInteger.ModPow(b, m, value);

			if (z.IsOne || z == value - 1)
			{
				continue;
			}

			bool witness = true;

			for (int j = 1; j < a && witness; ++j)
			{
				z = BigInteger.ModPow(z, 2, value);
				witness = z != value - 1;
			}

			if (witness)
			{
				return false;
			}
		}

		return true;
	}

	public static BigInteger RandomPrime(Random random, int bits)
	{
		while (true)
		{
			BigInteger candidate = RandomBits(random, bits) | BigInteger.One << bits - 1 | 1;

			if (IsProbablePrime(candidate, random))
			{
				return candidate;
			}
		}
	}

	public static byte[] ToBigEndian(BigInteger value, int length)
	{
		byte[] bytes = new byte[length];

		if (!value.TryWriteBytes(bytes.AsSpan(length - value.GetByteCount(true)), out _, true, true))
		{
			throw new ArgumentOutOfRangeException(nameof(value));
		}

		return bytes;
	}

	public static BigInteger FromBigEndian(ReadOnlySpan<byte> bytes)
	{
		return new BigInteger(bytes, true, true);
	}

	// The fields of an instance, its base classes' included, that hold a ulong or ulong values that are not all zero: what Dispose must have erased from an instance that holds nothing else of the kind.
	public static IEnumerable<string> NonZeroWords(object instance)
	{
		for (Type? type = instance.GetType(); type is not null; type = type.BaseType)
		{
			foreach (FieldInfo field in type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
			{
				object? value = field.GetValue(instance);

				if (value is ulong and not 0 || value is ulong[] words && words.Any(static word => word is not 0))
				{
					yield return $"{type.Name}.{field.Name}";
				}
			}
		}
	}

	public static object? GetField(object instance, string name)
	{
		FieldInfo field = instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new MissingFieldException(instance.GetType().Name, name);
		return field.GetValue(instance);
	}
}
