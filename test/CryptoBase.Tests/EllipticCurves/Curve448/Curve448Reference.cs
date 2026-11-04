using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

internal readonly record struct EdwardsValue(BigInteger X, BigInteger Y);

// Curve448, edwards448 and the twisted curve −x² + y² = 1 + (d − 1)x²y² from RFC 7748 and RFC 8032.
internal static class Curve448Reference
{
	internal static readonly BigInteger P = (BigInteger.One << 448) - (BigInteger.One << 224) - 1;

	internal static readonly BigInteger L = (BigInteger.One << 446) - BigInteger.Parse("13818066809895115352007386748515426880336692474882178609894547503885");

	internal static readonly BigInteger D = Mod(-39081);

	internal static readonly BigInteger TwistedD = Mod(-39082);

	internal const uint A24 = 39081;

	internal static readonly EdwardsValue Identity = new(0, 1);

	// RFC 8032 §5.2.
	internal static readonly EdwardsValue Base = new(
		BigInteger.Parse("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"),
		BigInteger.Parse("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"));

	internal static BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	internal static BigInteger Inverse(BigInteger value)
	{
		return ECReference.Inverse(Mod(value), P);
	}

	// p ≡ 3 (mod 4), so a root is value^((p + 1)/4).
	internal static BigInteger? SquareRoot(BigInteger value)
	{
		BigInteger root = BigInteger.ModPow(Mod(value), (P + 1) / 4, P);
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

	internal static byte[] EncodeInteger(BigInteger value, int length = 56)
	{
		byte[] bytes = new byte[length];

		if (!value.TryWriteBytes(bytes, out _, isUnsigned: true))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The value does not fit.");
		}

		return bytes;
	}

	// decodeScalar448 of RFC 7748 §5.
	internal static BigInteger DecodeScalar(ReadOnlySpan<byte> bytes)
	{
		byte[] clamped = bytes.ToArray();
		clamped[0] &= 252;
		clamped[55] |= 128;
		return DecodeInteger(clamped);
	}

	// The ladder of RFC 7748 §5 over all 448 bits of k; 0 for the point at infinity.
	internal static BigInteger Ladder(BigInteger k, BigInteger u)
	{
		u = Mod(u);
		BigInteger[] state = [1, 0, u, 1];
		bool swap = false;

		for (int t = 447; t >= 0; --t)
		{
			bool bit = !(k >> t).IsEven;
			swap ^= bit;

			if (swap)
			{
				state = [state[2], state[3], state[0], state[1]];
			}

			swap = bit;
			state = [.. LadderStep(state, u).Select(Mod)];
		}

		if (swap)
		{
			state = [state[2], state[3], state[0], state[1]];
		}

		return Mod(state[0] * Inverse(state[1]));
	}

	// Not reduced, so that the vector fields can be checked lane by lane.
	internal static BigInteger[] LadderStep(BigInteger[] state, BigInteger u)
	{
		BigInteger a = state[0] + state[1];
		BigInteger aa = a * a;
		BigInteger b = state[0] - state[1];
		BigInteger bb = b * b;
		BigInteger e = aa - bb;
		BigInteger c = state[2] + state[3];
		BigInteger d = state[2] - state[3];
		BigInteger da = d * a;
		BigInteger cb = c * b;
		BigInteger sum = da + cb;
		BigInteger difference = da - cb;
		return [aa * bb, e * (aa + A24 * e), sum * sum, u * difference * difference];
	}

	// decodeScalar448 of RFC 7748 §5, as bytes.
	internal static byte[] Clamp(ReadOnlySpan<byte> scalar)
	{
		byte[] clamped = scalar.ToArray();
		clamped[0] &= 252;
		clamped[^1] |= 128;
		return clamped;
	}

	// X448 of RFC 7748 §5.
	internal static byte[] X448Function(ReadOnlySpan<byte> k, ReadOnlySpan<byte> u)
	{
		return EncodeInteger(Ladder(DecodeScalar(k), DecodeInteger(u)));
	}

	internal static bool IsOnCurve(EdwardsValue point)
	{
		(BigInteger x, BigInteger y) = point;
		return x >= 0 && x < P && y >= 0 && y < P && Mod(x * x + y * y - 1 - D * x * x * y * y).IsZero;
	}

	internal static bool IsOnTwistedCurve(EdwardsValue point)
	{
		(BigInteger x, BigInteger y) = point;
		return x >= 0 && x < P && y >= 0 && y < P && Mod(-x * x + y * y - 1 - TwistedD * x * x * y * y).IsZero;
	}

	internal static EdwardsValue Add(EdwardsValue left, EdwardsValue right)
	{
		(BigInteger x1, BigInteger y1) = left;
		(BigInteger x2, BigInteger y2) = right;
		BigInteger t = Mod(D * x1 * x2 * y1 * y2);
		return new EdwardsValue(Mod((x1 * y2 + y1 * x2) * Inverse(1 + t)), Mod((y1 * y2 - x1 * x2) * Inverse(1 - t)));
	}

	// Exception-free only for points of odd order.
	internal static EdwardsValue TwistedAdd(EdwardsValue left, EdwardsValue right)
	{
		(BigInteger x1, BigInteger y1) = left;
		(BigInteger x2, BigInteger y2) = right;
		BigInteger t = Mod(TwistedD * x1 * x2 * y1 * y2);
		return new EdwardsValue(Mod((x1 * y2 + y1 * x2) * Inverse(1 + t)), Mod((y1 * y2 + x1 * x2) * Inverse(1 - t)));
	}

	internal static EdwardsValue Negate(EdwardsValue point)
	{
		return point with { X = Mod(-point.X) };
	}

	internal static EdwardsValue Multiply(EdwardsValue point, BigInteger k)
	{
		return Multiply(point, k, twisted: false);
	}

	// For a point of odd order.
	internal static EdwardsValue TwistedMultiply(EdwardsValue point, BigInteger k)
	{
		return Multiply(point, k, twisted: true);
	}

	// A 4-isogeny; Untwist ∘ Twist is multiplication by 4.
	internal static EdwardsValue Twist(EdwardsValue point)
	{
		(BigInteger x, BigInteger y) = point;
		return new EdwardsValue(Mod(2 * x * y * Inverse(y * y - x * x)), Mod((y * y + x * x) * Inverse(2 - y * y - x * x)));
	}

	internal static EdwardsValue Untwist(EdwardsValue point)
	{
		(BigInteger x, BigInteger y) = point;
		return new EdwardsValue(Mod(2 * x * y * Inverse(x * x + y * y)), Mod((y * y - x * x) * Inverse(2 - y * y + x * x)));
	}

	private static EdwardsValue Multiply(EdwardsValue point, BigInteger k, bool twisted)
	{
		(BigInteger X, BigInteger Y, BigInteger Z) result = (0, 1, 1);
		(BigInteger X, BigInteger Y, BigInteger Z) right = (point.X, point.Y, 1);

		for (long bit = k.GetBitLength() - 1; bit >= 0; --bit)
		{
			result = ProjectiveAdd(result, result, twisted);

			if (!(k >> (int)bit).IsEven)
			{
				result = ProjectiveAdd(result, right, twisted);
			}
		}

		BigInteger inverse = Inverse(result.Z);
		return new EdwardsValue(Mod(result.X * inverse), Mod(result.Y * inverse));
	}

	// RFC 8032 §5.2.4, with D + C in Y3 for the a = −1 of the twisted curve; the denominators are those of Add and TwistedAdd.
	private static (BigInteger X, BigInteger Y, BigInteger Z) ProjectiveAdd((BigInteger X, BigInteger Y, BigInteger Z) left, (BigInteger X, BigInteger Y, BigInteger Z) right, bool twisted)
	{
		BigInteger a = Mod(left.Z * right.Z);
		BigInteger b = Mod(a * a);
		BigInteger c = Mod(left.X * right.X);
		BigInteger d = Mod(left.Y * right.Y);
		BigInteger e = Mod((twisted ? TwistedD : D) * c * d);
		BigInteger f = Mod(b - e);
		BigInteger g = Mod(b + e);
		return (Mod(a * f * ((left.X + left.Y) * (right.X + right.Y) - c - d)), Mod(a * g * (twisted ? d + c : d - c)), Mod(f * g));
	}

	// RFC 8032 §5.2.2.
	internal static byte[] Encode(EdwardsValue point)
	{
		byte[] encoded = EncodeInteger(point.Y, 57);
		encoded[56] |= (byte)(point.X.IsEven ? 0 : 0x80);
		return encoded;
	}

	// RFC 8032 §5.2.3, strictly.
	internal static EdwardsValue? Decode(ReadOnlySpan<byte> encoded)
	{
		if (encoded.Length is not 57 || (encoded[56] & 0x7F) is not 0)
		{
			return null;
		}

		bool sign = encoded[56] >> 7 is 1;
		BigInteger y = DecodeInteger(encoded.Slice(0, 56));

		if (y >= P || SquareRoot((y * y - 1) * Inverse(D * y * y - 1)) is not { } x)
		{
			return null;
		}

		if (x.IsZero && sign)
		{
			return null;
		}

		return new EdwardsValue(x.IsEven == sign ? Mod(-x) : x, y);
	}

	// The 4-isogeny of RFC 7748 §4.2; 0 where x = 0.
	internal static BigInteger ToMontgomeryU(EdwardsValue point)
	{
		return Mod(point.Y * point.Y * Inverse(point.X * point.X));
	}

	internal static EdwardsValue[] TorsionPoints()
	{
		return [Identity, new EdwardsValue(1, 0), new EdwardsValue(0, P - 1), new EdwardsValue(P - 1, 0)];
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

	internal static EdwardsValue RandomPoint(Random random)
	{
		while (true)
		{
			BigInteger y = RandomBelow(random, P);
			byte[] encoded = EncodeInteger(y, 57);
			encoded[56] = (byte)(random.Next(2) << 7);

			if (Decode(encoded) is { } point)
			{
				return point;
			}
		}
	}
}
