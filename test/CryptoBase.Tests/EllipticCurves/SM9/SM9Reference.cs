using System.Globalization;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves.SM9;

// a0 + a1·u in Fp2 = Fp[u]/(u² + 2), plain values below p.
public readonly record struct Fp2Value(BigInteger A0, BigInteger A1)
{
	internal static Fp2Value Zero => new(0, 0);

	internal static Fp2Value One => new(1, 0);

	internal bool IsZero => A0.IsZero && A1.IsZero;

	public static Fp2Value operator +(Fp2Value left, Fp2Value right)
	{
		return new Fp2Value(SM9Reference.Mod(left.A0 + right.A0), SM9Reference.Mod(left.A1 + right.A1));
	}

	public static Fp2Value operator -(Fp2Value left, Fp2Value right)
	{
		return new Fp2Value(SM9Reference.Mod(left.A0 - right.A0), SM9Reference.Mod(left.A1 - right.A1));
	}

	public static Fp2Value operator -(Fp2Value value)
	{
		return Zero - value;
	}

	public static Fp2Value operator *(Fp2Value left, Fp2Value right)
	{
		return new Fp2Value(SM9Reference.Mod(left.A0 * right.A0 - 2 * left.A1 * right.A1), SM9Reference.Mod(left.A0 * right.A1 + left.A1 * right.A0));
	}

	public static Fp2Value operator *(Fp2Value left, BigInteger right)
	{
		return new Fp2Value(SM9Reference.Mod(left.A0 * right), SM9Reference.Mod(left.A1 * right));
	}

	internal Fp2Value Conjugate()
	{
		return new Fp2Value(A0, SM9Reference.Mod(-A1));
	}

	internal Fp2Value Inverse()
	{
		BigInteger inverse = SM9Reference.Inverse(A0 * A0 + 2 * A1 * A1);
		return new Fp2Value(SM9Reference.Mod(A0 * inverse), SM9Reference.Mod(-A1 * inverse));
	}

	internal Fp2Value Pow(BigInteger exponent)
	{
		Fp2Value result = One;

		for (int i = (int)exponent.GetBitLength() - 1; i >= 0; --i)
		{
			result *= result;

			if (!(exponent >> i & 1).IsZero)
			{
				result *= this;
			}
		}

		return result;
	}

	public override string ToString()
	{
		return $"({A1:X}, {A0:X})";
	}
}

// Σ C[i]·w^i in Fp12 = Fp2[w]/(w⁶ − u).
public sealed record Fp12Value(Fp2Value[] C)
{
	internal static Fp12Value One => new([Fp2Value.One, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero]);

	internal static Fp12Value FromFp2(Fp2Value value)
	{
		return new Fp12Value([value, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero]);
	}

	public static Fp12Value operator *(Fp12Value left, Fp12Value right)
	{
		Fp2Value[] product = new Fp2Value[11];
		Array.Fill(product, Fp2Value.Zero);

		for (int i = 0; i < 6; ++i)
		{
			for (int j = 0; j < 6; ++j)
			{
				product[i + j] += left.C[i] * right.C[j];
			}
		}

		Fp2Value u = new(0, 1);

		for (int k = 10; k >= 6; --k)
		{
			product[k - 6] += product[k] * u;
		}

		return new Fp12Value(product[..6]);
	}

	public static Fp12Value operator +(Fp12Value left, Fp12Value right)
	{
		return new Fp12Value(left.C.Zip(right.C, static (x, y) => x + y).ToArray());
	}

	public static Fp12Value operator -(Fp12Value left, Fp12Value right)
	{
		return new Fp12Value(left.C.Zip(right.C, static (x, y) => x - y).ToArray());
	}

	internal Fp12Value Pow(BigInteger exponent)
	{
		Fp12Value result = One;

		for (int i = (int)exponent.GetBitLength() - 1; i >= 0; --i)
		{
			result *= result;

			if (!(exponent >> i & 1).IsZero)
			{
				result *= this;
			}
		}

		return result;
	}

	// x with this·x = 1, by Gaussian elimination on the six columns this·w^j over Fp2.
	internal Fp12Value Inverse()
	{
		Fp2Value[,] system = new Fp2Value[6, 7];
		Fp12Value column = this;
		Fp12Value w = new([Fp2Value.Zero, Fp2Value.One, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero]);

		for (int j = 0; j < 6; ++j)
		{
			for (int i = 0; i < 6; ++i)
			{
				system[i, j] = column.C[i];
			}

			column *= w;
		}

		for (int i = 0; i < 6; ++i)
		{
			system[i, 6] = i is 0 ? Fp2Value.One : Fp2Value.Zero;
		}

		for (int k = 0; k < 6; ++k)
		{
			int pivot = k;

			while (system[pivot, k].IsZero)
			{
				++pivot;
			}

			for (int c = k; c < 7; ++c)
			{
				(system[k, c], system[pivot, c]) = (system[pivot, c], system[k, c]);
			}

			Fp2Value scale = system[k, k].Inverse();

			for (int c = k; c < 7; ++c)
			{
				system[k, c] *= scale;
			}

			for (int r = 0; r < 6; ++r)
			{
				Fp2Value factor = system[r, k];

				if (r == k || factor.IsZero)
				{
					continue;
				}

				for (int c = k; c < 7; ++c)
				{
					system[r, c] -= factor * system[k, c];
				}
			}
		}

		return new Fp12Value(Enumerable.Range(0, 6).Select(i => system[i, 6]).ToArray());
	}

	public bool Equals(Fp12Value? other)
	{
		return other is not null && C.SequenceEqual(other.C);
	}

	public override int GetHashCode()
	{
		return C.Aggregate(0, static (hash, c) => HashCode.Combine(hash, c));
	}

	// The 384 bytes of GM/T 0044.1 §7.2.6 as hex, the coefficients of w⁵, w², w⁴, w¹, w³ and w⁰, each u-coefficient first.
	internal string ToHex()
	{
		return string.Concat(new[] { 5, 2, 4, 1, 3, 0 }.Select(i => $"{SM9Reference.Hex(C[i].A1)}{SM9Reference.Hex(C[i].A0)}"));
	}

	internal static Fp12Value FromHex(string hex)
	{
		BigInteger[] values = SM9Reference.ParseValues(hex, 12);
		Fp2Value[] c = new Fp2Value[6];
		int[] order = [5, 2, 4, 1, 3, 0];

		for (int k = 0; k < 6; ++k)
		{
			c[order[k]] = new Fp2Value(values[2 * k + 1], values[2 * k]);
		}

		return new Fp12Value(c);
	}

	public override string ToString()
	{
		return ToHex();
	}
}

public sealed record G1Value(BigInteger X, BigInteger Y);

public sealed record G2Value(Fp2Value X, Fp2Value Y);

// The parameters of GM/T 0044.5 §3 and the arithmetic of its curves, tower and pairing from their definitions, to check the implementation against: affine points, where null is the point at infinity, and the R-ate pairing of GM/T 0044.1 B.6.2 step by step.
internal static class SM9Reference
{
	internal static readonly BigInteger T = BigInteger.Parse("600000000058F98A", NumberStyles.HexNumber);

	internal static readonly BigInteger P = 36 * BigInteger.Pow(T, 4) + 36 * BigInteger.Pow(T, 3) + 24 * T * T + 6 * T + 1;

	internal static readonly BigInteger N = 36 * BigInteger.Pow(T, 4) + 36 * BigInteger.Pow(T, 3) + 18 * T * T + 6 * T + 1;

	// The cofactor of G2 in E'(Fp2).
	internal static readonly BigInteger TwistCofactor = 2 * P - N;

	internal static readonly BigInteger MontgomeryR = BigInteger.One << 260;

	internal static readonly Fp2Value U = new(0, 1);

	internal static readonly Fp2Value TwistB = new(0, 5);

	internal static readonly G1Value P1 = new(Parse("93DE051D 62BF718F F5ED0704 487D01D6 E1E40869 09DC3280 E8C4E481 7C66DDDD"), Parse("21FE8DDA 4F21E607 63106512 5C395BBC 1C1C00CB FA602435 0C464CD7 0A3EA616"));

	internal static readonly G2Value P2 = new(Fp2("85AEF3D0 78640C98 597B6027 B441A01F F1DD2C19 0F5E93C4 54806C11 D8806141", "37227552 92130B08 D2AAB97F D34EC120 EE265948 D19C17AB F9B7213B AF82D65B"), Fp2("17509B09 2E845C12 66BA0D26 2CBEE6ED 0736A96F A347C8BD 856DC76B 84EBEB96", "A7CF28D5 19BE3DA6 5F317015 3D278FF2 47EFBA98 A71A0811 6215BBA5 C999A7C7"));

	internal static BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	internal static BigInteger ModN(BigInteger value)
	{
		BigInteger remainder = value % N;
		return remainder.Sign < 0 ? remainder + N : remainder;
	}

	internal static BigInteger Inverse(BigInteger value)
	{
		return ECReference.Inverse(Mod(value), P);
	}

	// A value written in hex, spaces allowed.
	internal static BigInteger Parse(string hex)
	{
		return BigInteger.Parse("0" + string.Concat(hex.Where(static c => !char.IsWhiteSpace(c))), NumberStyles.HexNumber);
	}

	// An element of Fp2 written as GM/T 0044.5 writes it, (a1, a0).
	private static Fp2Value Fp2(string a1, string a0)
	{
		return new Fp2Value(Parse(a0), Parse(a1));
	}

	internal static string Hex(BigInteger value, int length = 32)
	{
		return Convert.ToHexString(Encode(value, length));
	}

	internal static byte[] Encode(BigInteger value, int length = 32)
	{
		byte[] minimal = value.ToByteArray(isUnsigned: true, isBigEndian: true);

		if (minimal.Length > length)
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The value does not fit.");
		}

		byte[] bytes = new byte[length];
		minimal.CopyTo(bytes, length - minimal.Length);
		return bytes;
	}

	// count values of 32 bytes each, from hex with any separators.
	internal static BigInteger[] ParseValues(string hex, int count)
	{
		string digits = string.Concat(hex.Where(Uri.IsHexDigit));

		if (digits.Length != 64 * count)
		{
			throw new ArgumentException($"Expected {count} values, got {digits.Length} hex digits.", nameof(hex));
		}

		return Enumerable.Range(0, count).Select(i => BigInteger.Parse("0" + digits.Substring(64 * i, 64), NumberStyles.HexNumber)).ToArray();
	}

	internal static G1Value G1(string x, string y)
	{
		return new G1Value(Parse(x), Parse(y));
	}

	internal static G2Value G2(string x1, string x0, string y1, string y0)
	{
		return new G2Value(Fp2(x1, x0), Fp2(y1, y0));
	}

	internal static bool IsOnTwist(G2Value point)
	{
		return (point.Y * point.Y - point.X * point.X * point.X - TwistB).IsZero;
	}

	internal static G1Value? Add(G1Value? left, G1Value? right)
	{
		if (left is null)
		{
			return right;
		}

		if (right is null)
		{
			return left;
		}

		BigInteger lambda;

		if (left.X == right.X)
		{
			if (Mod(left.Y + right.Y).IsZero)
			{
				return null;
			}

			lambda = Mod(3 * left.X * left.X * Inverse(2 * left.Y));
		}
		else
		{
			lambda = Mod((right.Y - left.Y) * Inverse(right.X - left.X));
		}

		BigInteger x = Mod(lambda * lambda - left.X - right.X);
		return new G1Value(x, Mod(lambda * (left.X - x) - left.Y));
	}

	internal static G1Value? Negate(G1Value? point)
	{
		return point is null ? null : point with { Y = Mod(-point.Y) };
	}

	internal static G1Value? Multiply(G1Value? point, BigInteger scalar)
	{
		if (scalar.Sign < 0)
		{
			return Multiply(Negate(point), -scalar);
		}

		G1Value? result = null;

		for (int i = (int)scalar.GetBitLength() - 1; i >= 0; --i)
		{
			result = Add(result, result);

			if (!(scalar >> i & 1).IsZero)
			{
				result = Add(result, point);
			}
		}

		return result;
	}

	internal static G2Value? Add(G2Value? left, G2Value? right)
	{
		if (left is null)
		{
			return right;
		}

		if (right is null)
		{
			return left;
		}

		Fp2Value lambda;

		if (left.X == right.X)
		{
			if ((left.Y + right.Y).IsZero)
			{
				return null;
			}

			lambda = left.X * left.X * 3 * (left.Y * 2).Inverse();
		}
		else
		{
			lambda = (right.Y - left.Y) * (right.X - left.X).Inverse();
		}

		Fp2Value x = lambda * lambda - left.X - right.X;
		return new G2Value(x, lambda * (left.X - x) - left.Y);
	}

	internal static G2Value? Negate(G2Value? point)
	{
		return point is null ? null : point with { Y = -point.Y };
	}

	internal static G2Value? Multiply(G2Value? point, BigInteger scalar)
	{
		if (scalar.Sign < 0)
		{
			return Multiply(Negate(point), -scalar);
		}

		G2Value? result = null;

		for (int i = (int)scalar.GetBitLength() - 1; i >= 0; --i)
		{
			result = Add(result, result);

			if (!(scalar >> i & 1).IsZero)
			{
				result = Add(result, point);
			}
		}

		return result;
	}

	// The p-power Frobenius of E(Fp12) carried to the twist through ψ6(x, y) = (x·w⁻², y·w⁻³): (x̄·w^(2(p − 1)), ȳ·w^(3(p − 1))), both factors in Fp.
	internal static G2Value Frobenius(G2Value point)
	{
		Fp2Value cx = U.Pow((P - 1) / 3).Inverse();
		Fp2Value cy = U.Pow((P - 1) / 2).Inverse();
		return new G2Value(point.X.Conjugate() * cx, point.Y.Conjugate() * cy);
	}

	// A point of E'(Fp2) for x, if x³ + 5u is a square there, by the root of a square in Fp2 = Fp(√−2) through its norm.
	internal static G2Value? TwistPoint(Fp2Value x)
	{
		Fp2Value rhs = x * x * x + TwistB;
		Fp2Value? root = SquareRoot(rhs);
		return root is { } y ? new G2Value(x, y) : null;
	}

	// A root a + b·u of v0 + v1·u, or null if there is none: a² − 2b² = v0 and a² + 2b² = ±√(v0² + 2v1²), the norm, so a² = (v0 ± √norm)/2, and then b = v1/(2a), or b² = −v0/2 where a = 0.
	private static Fp2Value? SquareRoot(Fp2Value value)
	{
		if (value.IsZero)
		{
			return Fp2Value.Zero;
		}

		BigInteger norm = Mod(value.A0 * value.A0 + 2 * value.A1 * value.A1);
		BigInteger? s = FpSquareRoot(norm);

		if (s is not { } root)
		{
			return null;
		}

		foreach (BigInteger sign in (BigInteger[])[root, Mod(-root)])
		{
			BigInteger aa = Mod((value.A0 + sign) * Inverse(2));

			if (FpSquareRoot(aa) is { IsZero: false } a)
			{
				BigInteger b = Mod(value.A1 * Inverse(2 * a));
				Fp2Value candidate = new(a, b);

				if (candidate * candidate == value)
				{
					return candidate;
				}
			}
			else if (aa.IsZero && FpSquareRoot(Mod(-value.A0 * Inverse(2))) is { } b2)
			{
				Fp2Value candidate = new(0, b2);

				if (candidate * candidate == value)
				{
					return candidate;
				}
			}
		}

		return null;
	}

	// Tonelli–Shanks.
	private static BigInteger? FpSquareRoot(BigInteger value)
	{
		value = Mod(value);

		if (value.IsZero)
		{
			return BigInteger.Zero;
		}

		if (BigInteger.ModPow(value, (P - 1) / 2, P) != 1)
		{
			return null;
		}

		BigInteger q = P - 1;
		int s = 0;

		while (q.IsEven)
		{
			q >>= 1;
			++s;
		}

		BigInteger z = 2;

		while (BigInteger.ModPow(z, (P - 1) / 2, P) == 1)
		{
			++z;
		}

		BigInteger c = BigInteger.ModPow(z, q, P);
		BigInteger r = BigInteger.ModPow(value, (q + 1) / 2, P);
		BigInteger t = BigInteger.ModPow(value, q, P);
		int m = s;

		while (t != 1)
		{
			int i = 0;
			BigInteger t2 = t;

			while (t2 != 1)
			{
				t2 = t2 * t2 % P;
				++i;
			}

			BigInteger b = BigInteger.ModPow(c, BigInteger.One << m - i - 1, P);
			r = r * b % P;
			c = b * b % P;
			t = t * c % P;
			m = i;
		}

		return r;
	}

	// e(P, Q) by GM/T 0044.1 B.6.2: the Miller loop over the bits of a = 6t + 2 with lines through points of E(Fp12), ψ6(x, y) = (x·w⁻², y·w⁻³), evaluated at P, then the lines to π(Q) and −π²(Q), and the power (p¹² − 1)/N.
	internal static Fp12Value Pairing(G1Value p, G2Value q)
	{
		Fp12Value wInverse = new Fp12Value([Fp2Value.Zero, Fp2Value.One, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero, Fp2Value.Zero]).Inverse();
		Fp12Value w2 = wInverse * wInverse;
		Fp12Value w3 = w2 * wInverse;
		(Fp12Value X, Fp12Value Y) untwisted = (Fp12Value.FromFp2(q.X) * w2, Fp12Value.FromFp2(q.Y) * w3);
		(Fp12Value X, Fp12Value Y) frobenius = (untwisted.X.Pow(P), untwisted.Y.Pow(P));
		(Fp12Value X, Fp12Value Y) frobenius2 = (frobenius.X.Pow(P), frobenius.Y.Pow(P));
		Fp12Value xp = Fp12Value.FromFp2(new Fp2Value(p.X, 0));
		Fp12Value yp = Fp12Value.FromFp2(new Fp2Value(p.Y, 0));
		BigInteger a = 6 * T + 2;
		(Fp12Value X, Fp12Value Y) t = untwisted;
		Fp12Value f = Fp12Value.One;

		for (int i = (int)a.GetBitLength() - 2; i >= 0; --i)
		{
			f = f * f * LineAndAdd(ref t, t, xp, yp);

			if (!(a >> i & 1).IsZero)
			{
				f *= LineAndAdd(ref t, untwisted, xp, yp);
			}
		}

		f *= LineAndAdd(ref t, frobenius, xp, yp);
		(Fp12Value X, Fp12Value Y) negated = (frobenius2.X, Fp12Value.One - Fp12Value.One - frobenius2.Y);
		f *= LineAndAdd(ref t, negated, xp, yp);
		return f.Pow((BigInteger.Pow(P, 12) - 1) / N);
	}

	// g_{U,V}(P) = λ(x_P − x_V) − y_P + y_V of GM/T 0044.1 for points U and V that are neither equal to the negation of the other nor at infinity, and U + V into u by the same λ.
	private static Fp12Value LineAndAdd(ref (Fp12Value X, Fp12Value Y) u, (Fp12Value X, Fp12Value Y) v, Fp12Value xp, Fp12Value yp)
	{
		Fp12Value lambda = Slope(u, v);
		Fp12Value line = lambda * (xp - v.X) - yp + v.Y;
		Fp12Value x = lambda * lambda - u.X - v.X;
		u = (x, lambda * (u.X - x) - u.Y);
		return line;
	}

	private static Fp12Value Slope((Fp12Value X, Fp12Value Y) u, (Fp12Value X, Fp12Value Y) v)
	{
		if (u.X.Equals(v.X))
		{
			Fp12Value three = Fp12Value.FromFp2(new Fp2Value(3, 0));
			Fp12Value two = Fp12Value.FromFp2(new Fp2Value(2, 0));
			return three * u.X * u.X * (two * u.Y).Inverse();
		}

		return (u.Y - v.Y) * (u.X - v.X).Inverse();
	}
}
