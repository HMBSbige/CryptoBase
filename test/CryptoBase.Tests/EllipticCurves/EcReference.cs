using CryptoBase.Tests.Wycheproof;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

// An affine point with plain coordinates; where a CurvePoint? is expected, null is the point at infinity.
internal sealed record CurvePoint(BigInteger X, BigInteger Y);

// Plain homogeneous coordinates (X : Y : Z).
internal readonly record struct ProjectiveValue(BigInteger X, BigInteger Y, BigInteger Z);

// Plain Jacobian coordinates (X : Y : Z).
internal readonly record struct JacobianValue(BigInteger X, BigInteger Y, BigInteger Z);

// Affine arithmetic from the curve parameters alone, to check EcGroup against.
internal sealed class EcReference(EcCurveTestVector curve)
{
	internal BigInteger P { get; } = ModulusCase.Decode(curve.P);

	internal BigInteger A { get; } = ModulusCase.Decode(curve.A);

	internal BigInteger B { get; } = ModulusCase.Decode(curve.B);

	internal BigInteger N { get; } = ModulusCase.Decode(curve.N);

	internal CurvePoint Generator { get; } = new(ModulusCase.Decode(curve.Gx), ModulusCase.Decode(curve.Gy));

	internal BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	internal BigInteger Inverse(BigInteger value)
	{
		BigInteger remainder = Mod(value);
		BigInteger divisor = P;
		BigInteger x = 1;
		BigInteger previous = 0;

		if (remainder.IsZero)
		{
			throw new DivideByZeroException();
		}

		while (!divisor.IsZero)
		{
			BigInteger quotient = BigInteger.DivRem(remainder, divisor, out BigInteger next);
			(remainder, divisor) = (divisor, next);
			(x, previous) = (previous, x - quotient * previous);
		}

		return Mod(x);
	}

	// Inverts all the values with a single inversion of their product.
	internal BigInteger[] Inverse(BigInteger[] values)
	{
		BigInteger[] inverses = new BigInteger[values.Length];
		BigInteger product = 1;

		for (int i = 0; i < values.Length; ++i)
		{
			inverses[i] = product;
			product = Mod(product * values[i]);
		}

		BigInteger inverse = Inverse(product);

		for (int i = values.Length - 1; i >= 0; --i)
		{
			inverses[i] = Mod(inverses[i] * inverse);
			inverse = Mod(inverse * values[i]);
		}

		return inverses;
	}

	internal bool IsOnCurve(CurvePoint point)
	{
		return point.X >= 0 && point.X < P && point.Y >= 0 && point.Y < P && Mod(point.Y * point.Y - Cubic(point.X)) == 0;
	}

	// Also requires coordinates below p and rejects (0 : 0 : 0).
	internal bool IsOnProjectiveCurve(ProjectiveValue value)
	{
		(BigInteger x, BigInteger y, BigInteger z) = value;
		bool reduced = x >= 0 && x < P && y >= 0 && y < P && z >= 0 && z < P;
		return reduced && !(x.IsZero && y.IsZero && z.IsZero) && Mod(y * y * z - x * x * x - A * x * z * z - B * z * z * z) == 0;
	}

	internal CurvePoint? Negate(CurvePoint? point)
	{
		return point is null ? null : new CurvePoint(point.X, Mod(-point.Y));
	}

	internal CurvePoint? Add(CurvePoint? left, CurvePoint? right)
	{
		return Add([left], [right])[0];
	}

	// Adds pairwise with a single inversion for all the slopes.
	internal CurvePoint?[] Add(IReadOnlyList<CurvePoint?> left, IReadOnlyList<CurvePoint?> right)
	{
		(BigInteger Rise, BigInteger Run)?[] slopes = [.. left.Zip(right, Slope)];
		BigInteger[] inverses = Inverse([.. slopes.Select(static slope => slope?.Run ?? 1)]);
		CurvePoint?[] sums = new CurvePoint?[slopes.Length];

		for (int i = 0; i < sums.Length; ++i)
		{
			sums[i] = (left[i], right[i], slopes[i]) switch
			{
				(null, var point, _) => point,
				(var point, null, _) => point,
				({ } l, { } r, var (rise, _)) => Sum(l, r, Mod(rise * inverses[i])),
				_ => null
			};
		}

		return sums;
	}

	internal CurvePoint? Multiply(CurvePoint? point, BigInteger scalar)
	{
		return Multiply(point, [scalar])[0];
	}

	// Doubles and adds for all the scalars at once, so that each step takes a single inversion.
	internal CurvePoint?[] Multiply(CurvePoint? point, IReadOnlyCollection<BigInteger> scalars)
	{
		CurvePoint?[] products = new CurvePoint?[scalars.Count];

		for (long bit = scalars.Max(static scalar => scalar.GetBitLength()) - 1; bit >= 0; --bit)
		{
			int shift = (int)bit;
			products = Add(products, products);
			products = Add(products, [.. scalars.Select(scalar => (scalar >> shift).IsEven ? null : point)]);
		}

		return products;
	}

	internal CurvePoint? ToAffine(ProjectiveValue value)
	{
		if (value.Z.IsZero)
		{
			return null;
		}

		BigInteger inverse = Inverse(value.Z);
		return new CurvePoint(Mod(value.X * inverse), Mod(value.Y * inverse));
	}

	internal ProjectiveValue Randomize(CurvePoint? point, Random random)
	{
		BigInteger lambda = 1 + RandomBelow(random, P - 1);
		return point is null ? new ProjectiveValue(0, lambda, 0) : new ProjectiveValue(Mod(lambda * point.X), Mod(lambda * point.Y), lambda);
	}

	// Also requires coordinates below p.
	internal bool IsOnJacobianCurve(JacobianValue value)
	{
		(BigInteger x, BigInteger y, BigInteger z) = value;
		bool reduced = x >= 0 && x < P && y >= 0 && y < P && z >= 0 && z < P;
		BigInteger zz = z * z;
		return reduced && (z.IsZero || Mod(y * y - x * x * x - A * x * zz * zz - B * zz * zz * zz).IsZero);
	}

	internal CurvePoint? ToAffine(JacobianValue value)
	{
		if (value.Z.IsZero)
		{
			return null;
		}

		BigInteger inverse = Inverse(value.Z);
		BigInteger square = Mod(inverse * inverse);
		return new CurvePoint(Mod(value.X * square), Mod(value.Y * square * inverse));
	}

	// The point at infinity gets random X and Y with Z = 0.
	internal JacobianValue RandomizeJacobian(CurvePoint? point, Random random)
	{
		BigInteger lambda = 1 + RandomBelow(random, P - 1);
		BigInteger square = Mod(lambda * lambda);
		return point is null
			? new JacobianValue(RandomBelow(random, P), RandomBelow(random, P), 0)
			: new JacobianValue(Mod(square * point.X), Mod(square * lambda * point.Y), lambda);
	}

	internal CurvePoint PublicKey(BigInteger privateKey)
	{
		return Multiply(Generator, privateKey) ?? throw new ArgumentOutOfRangeException(nameof(privateKey), privateKey, "The private key is a multiple of n.");
	}

	internal CurvePoint RandomPoint(Random random)
	{
		while (true)
		{
			BigInteger x = RandomBelow(random, P);

			if (SquareRoot(Cubic(x)) is { } y)
			{
				return new CurvePoint(x, random.Next(2) is 0 ? y : Mod(-y));
			}
		}
	}

	internal CurvePoint PointWithXFrom(BigInteger start)
	{
		for (BigInteger x = start;; ++x)
		{
			if (SquareRoot(Cubic(x)) is { } y)
			{
				return new CurvePoint(x, y);
			}
		}
	}

	// Takes the first y whose cubic x³ + ax + b − y² has a single root: its gcd with X^p − X is the product of X − x over the roots, so it is then linear.
	internal CurvePoint PointWithYFrom(BigInteger start)
	{
		for (BigInteger y = start;; ++y)
		{
			BigInteger[] cubic = [Mod(B - y * y), A, 0, 1];
			BigInteger[] power = [1];

			for (long bit = P.GetBitLength() - 1; bit >= 0; --bit)
			{
				power = Remainder(Product(power, power), cubic);

				if (!(P >> (int)bit).IsEven)
				{
					power = Remainder(Product(power, [0, 1]), cubic);
				}
			}

			BigInteger[] difference = [.. power, 0, 0];
			--difference[1];

			if (Gcd(cubic, Trim(difference)) is [var constant, var linear])
			{
				return new CurvePoint(Mod(-constant * Inverse(linear)), y);
			}
		}
	}

	internal static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		byte[] bytes = new byte[bound.GetByteCount(isUnsigned: true)];
		BigInteger mask = (BigInteger.One << (int)bound.GetBitLength()) - 1;

		while (true)
		{
			random.NextBytes(bytes);
			BigInteger value = ModulusCase.Decode(bytes) & mask;

			if (value < bound)
			{
				return value;
			}
		}
	}

	private BigInteger Cubic(BigInteger x)
	{
		return Mod(x * x * x + A * x + B);
	}

	// The line through left and right, the tangent if they are equal; null if either is the point at infinity or the line is vertical.
	private (BigInteger Rise, BigInteger Run)? Slope(CurvePoint? left, CurvePoint? right)
	{
		return (left, right) switch
		{
			({ } l, { } r) when l.X != r.X => (r.Y - l.Y, r.X - l.X),
			({ } l, { } r) when !Mod(l.Y + r.Y).IsZero => (3 * l.X * l.X + A, 2 * l.Y),
			_ => null
		};
	}

	private CurvePoint Sum(CurvePoint left, CurvePoint right, BigInteger slope)
	{
		BigInteger x = Mod(slope * slope - left.X - right.X);
		return new CurvePoint(x, Mod(slope * (left.X - x) - left.Y));
	}

	// Returns null if square has no root.
	private BigInteger? SquareRoot(BigInteger square)
	{
		if (P % 4 != 3)
		{
			throw new NotSupportedException("The square root needs p ≡ 3 (mod 4).");
		}

		BigInteger root = BigInteger.ModPow(square, (P + 1) / 4, P);
		return Mod(root * root - square).IsZero ? root : null;
	}

	// Polynomials over the field of p are coefficients from the constant term up, with no zero at the top.
	private BigInteger[] Trim(BigInteger[] coefficients)
	{
		int length = coefficients.Length;

		while (length > 0 && Mod(coefficients[length - 1]).IsZero)
		{
			--length;
		}

		return [.. coefficients.Take(length).Select(Mod)];
	}

	private BigInteger[] Product(BigInteger[] left, BigInteger[] right)
	{
		BigInteger[] product = new BigInteger[Math.Max(left.Length + right.Length - 1, 0)];

		for (int i = 0; i < left.Length; ++i)
		{
			for (int j = 0; j < right.Length; ++j)
			{
				product[i + j] += left[i] * right[j];
			}
		}

		return Trim(product);
	}

	private BigInteger[] Remainder(BigInteger[] dividend, BigInteger[] divisor)
	{
		BigInteger[] remainder = [.. dividend];
		BigInteger inverse = Inverse(divisor[^1]);

		for (int top = remainder.Length - 1; top >= divisor.Length - 1; --top)
		{
			BigInteger factor = Mod(remainder[top] * inverse);

			for (int j = 0; j < divisor.Length; ++j)
			{
				remainder[top - divisor.Length + 1 + j] -= factor * divisor[j];
			}
		}

		return Trim(remainder);
	}

	private BigInteger[] Gcd(BigInteger[] left, BigInteger[] right)
	{
		while (right.Length is not 0)
		{
			(left, right) = (right, Remainder(left, right));
		}

		return left;
	}
}
