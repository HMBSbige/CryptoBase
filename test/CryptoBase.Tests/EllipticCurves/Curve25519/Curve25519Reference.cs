using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

// An affine point of edwards25519 with plain coordinates.
internal readonly record struct EdwardsValue(BigInteger X, BigInteger Y);

// Curve25519 and edwards25519 from their definitions in RFC 7748 and RFC 8032, with BigInteger, to check the library against.
internal static class Curve25519Reference
{
	internal static readonly BigInteger P = (BigInteger.One << 255) - 19;

	internal static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

	internal static readonly BigInteger D = Mod(-121665 * Inverse(121666));

	internal static readonly BigInteger SqrtMinusOne = BigInteger.ModPow(2, (P - 1) / 4, P);

	internal static readonly EdwardsValue Identity = new(0, 1);

	// The y of B is 4/5 and its x is even.
	internal static readonly EdwardsValue Base = Decode(EncodeInteger(Mod(4 * Inverse(5)))) ?? throw new InvalidOperationException("4/5 is not the y of a point.");

	internal static BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	internal static BigInteger Inverse(BigInteger value)
	{
		return BigInteger.ModPow(Mod(value), P - 2, P);
	}

	// A square root of value, or null if it has none: for p ≡ 5 (mod 8), value^((p + 3)/8) or that times sqrt(−1).
	internal static BigInteger? SquareRoot(BigInteger value)
	{
		BigInteger root = BigInteger.ModPow(Mod(value), (P + 3) / 8, P);

		if (Mod(root * root - value).IsZero)
		{
			return root;
		}

		root = Mod(root * SqrtMinusOne);
		return Mod(root * root - value).IsZero ? root : null;
	}

	internal static bool IsSquare(BigInteger value)
	{
		return SquareRoot(value) is not null;
	}

	internal static BigInteger DecodeInteger(ReadOnlySpan<byte> bytes)
	{
		return new BigInteger(bytes, isUnsigned: true);
	}

	internal static byte[] EncodeInteger(BigInteger value, int length = 32)
	{
		byte[] bytes = new byte[length];

		if (!value.TryWriteBytes(bytes, out _, isUnsigned: true))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The value does not fit.");
		}

		return bytes;
	}

	// decodeUCoordinate of RFC 7748 §5: little-endian with bit 255 masked, and not reduced.
	internal static BigInteger DecodeU(ReadOnlySpan<byte> bytes)
	{
		return DecodeInteger(bytes) & (BigInteger.One << 255) - 1;
	}

	// decodeScalar25519 of RFC 7748 §5.
	internal static BigInteger DecodeScalar(ReadOnlySpan<byte> bytes)
	{
		byte[] clamped = bytes.ToArray();
		clamped[0] &= 248;
		clamped[31] &= 127;
		clamped[31] |= 64;
		return DecodeInteger(clamped);
	}

	// The ladder of RFC 7748 §5, transcribed.
	internal static BigInteger Ladder(BigInteger k, BigInteger u)
	{
		BigInteger x1 = Mod(u);
		BigInteger x2 = 1;
		BigInteger z2 = 0;
		BigInteger x3 = x1;
		BigInteger z3 = 1;
		bool swap = false;

		for (int t = 254; t >= 0; --t)
		{
			bool bit = !(k >> t).IsEven;
			swap ^= bit;

			if (swap)
			{
				(x2, x3) = (x3, x2);
				(z2, z3) = (z3, z2);
			}

			swap = bit;
			BigInteger a = Mod(x2 + z2);
			BigInteger aa = Mod(a * a);
			BigInteger b = Mod(x2 - z2);
			BigInteger bb = Mod(b * b);
			BigInteger e = Mod(aa - bb);
			BigInteger c = Mod(x3 + z3);
			BigInteger d = Mod(x3 - z3);
			BigInteger da = Mod(d * a);
			BigInteger cb = Mod(c * b);
			x3 = Mod((da + cb) * (da + cb));
			z3 = Mod(x1 * (da - cb) * (da - cb));
			x2 = Mod(aa * bb);
			z2 = Mod(e * (aa + 121665 * e));
		}

		if (swap)
		{
			x2 = x3;
			z2 = z3;
		}

		return Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
	}

	internal static byte[] X25519Function(ReadOnlySpan<byte> k, ReadOnlySpan<byte> u)
	{
		return EncodeInteger(Ladder(DecodeScalar(k), DecodeU(u)));
	}

	internal static bool IsOnCurve(EdwardsValue point)
	{
		(BigInteger x, BigInteger y) = point;
		return x >= 0 && x < P && y >= 0 && y < P && Mod(-x * x + y * y - 1 - D * x * x * y * y).IsZero;
	}

	internal static EdwardsValue Add(EdwardsValue left, EdwardsValue right)
	{
		(BigInteger x1, BigInteger y1) = left;
		(BigInteger x2, BigInteger y2) = right;
		BigInteger t = Mod(D * x1 * x2 * y1 * y2);
		return new EdwardsValue(Mod((x1 * y2 + y1 * x2) * Inverse(1 + t)), Mod((y1 * y2 + x1 * x2) * Inverse(1 - t)));
	}

	internal static EdwardsValue Negate(EdwardsValue point)
	{
		return point with { X = Mod(-point.X) };
	}

	// Double and add from the top bit, for any k ≥ 0, in projective coordinates (X : Y : Z) with x = X/Z and y = Y/Z, so that only the result is inverted.
	internal static EdwardsValue Multiply(EdwardsValue point, BigInteger k)
	{
		(BigInteger X, BigInteger Y, BigInteger Z) result = (0, 1, 1);
		(BigInteger X, BigInteger Y, BigInteger Z) right = (point.X, point.Y, 1);

		for (long bit = k.GetBitLength() - 1; bit >= 0; --bit)
		{
			result = ProjectiveAdd(result, result);

			if (!(k >> (int)bit).IsEven)
			{
				result = ProjectiveAdd(result, right);
			}
		}

		BigInteger inverse = Inverse(result.Z);
		return new EdwardsValue(Mod(result.X * inverse), Mod(result.Y * inverse));
	}

	// The addition law of Add with its denominators multiplied out: A = Z1Z2, B = A², C = X1X2, D = Y1Y2, E = dCD, F = B − E and G = B + E give X3 = AF((X1 + Y1)(X2 + Y2) − C − D), Y3 = AG(D + C) and Z3 = FG.
	private static (BigInteger X, BigInteger Y, BigInteger Z) ProjectiveAdd((BigInteger X, BigInteger Y, BigInteger Z) left, (BigInteger X, BigInteger Y, BigInteger Z) right)
	{
		BigInteger a = Mod(left.Z * right.Z);
		BigInteger b = Mod(a * a);
		BigInteger c = Mod(left.X * right.X);
		BigInteger d = Mod(left.Y * right.Y);
		BigInteger e = Mod(D * c * d);
		BigInteger f = Mod(b - e);
		BigInteger g = Mod(b + e);
		return (Mod(a * f * ((left.X + left.Y) * (right.X + right.Y) - c - d)), Mod(a * g * (d + c)), Mod(f * g));
	}

	// RFC 8032 §5.1.2.
	internal static byte[] Encode(EdwardsValue point)
	{
		byte[] encoded = EncodeInteger(point.Y);
		encoded[31] |= (byte)(point.X.IsEven ? 0 : 0x80);
		return encoded;
	}

	// RFC 8032 §5.1.3, strictly: null for a y of p or more, no x, or x = 0 with the sign bit set.
	internal static EdwardsValue? Decode(ReadOnlySpan<byte> encoded)
	{
		if (encoded.Length is not 32)
		{
			return null;
		}

		bool sign = encoded[31] >> 7 is 1;
		BigInteger y = DecodeU(encoded);

		if (y >= P || SquareRoot((y * y - 1) * Inverse(D * y * y + 1)) is not { } x)
		{
			return null;
		}

		if (x.IsZero && sign)
		{
			return null;
		}

		return new EdwardsValue(x.IsEven == sign ? Mod(-x) : x, y);
	}

	// u = (1 + y)/(1 − y), and 0 for the identity.
	internal static BigInteger ToMontgomeryU(EdwardsValue point)
	{
		return Mod((1 + point.Y) * Inverse(1 - point.Y));
	}

	// The eight points of order dividing 8, all multiples of one of order 8.
	internal static EdwardsValue[] TorsionPoints()
	{
		EdwardsValue generator = OrderEightPoint();
		EdwardsValue[] points = new EdwardsValue[8];
		points[0] = Identity;

		for (int i = 1; i < points.Length; ++i)
		{
			points[i] = Add(points[i - 1], generator);
		}

		return points;
	}

	// [L]Q for the first point Q, by y, whose [4L]Q is not the identity.
	internal static EdwardsValue OrderEightPoint()
	{
		for (BigInteger y = 2; ; ++y)
		{
			if (Decode(EncodeInteger(y)) is not { } q)
			{
				continue;
			}

			EdwardsValue candidate = Multiply(q, L);

			if (Multiply(candidate, 4) != Identity)
			{
				return candidate;
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
			BigInteger value = new BigInteger(bytes, isUnsigned: true) & mask;

			if (value < bound)
			{
				return value;
			}
		}
	}

	// A random point of the whole group, of any order.
	internal static EdwardsValue RandomPoint(Random random)
	{
		while (true)
		{
			BigInteger y = RandomBelow(random, P);
			byte[] encoded = EncodeInteger(y);
			encoded[31] |= (byte)(random.Next(2) << 7);

			if (Decode(encoded) is { } point)
			{
				return point;
			}
		}
	}
}
