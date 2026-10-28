using CryptoBase.EllipticCurves;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace CryptoBase.Tests.EllipticCurves;

// Which input, if any, an operation writes its result over.
public enum ResultAliasing
{
	None,
	Left,
	Right
}

public abstract class ModulusCase
{
	private static readonly ulong[] LimbPatterns = [0, 1, 1UL << 63, ulong.MaxValue - 1, ulong.MaxValue];

	public static IEnumerable<ModulusCase> All()
	{
		yield return new Case<P256Field>("secp256r1", false);
		yield return new Case<P256Order>("secp256r1", true);
		yield return new Case<P384Field>("secp384r1", false);
		yield return new Case<P384Order>("secp384r1", true);
		yield return new Case<P521Field>("secp521r1", false);
		yield return new Case<P521Order>("secp521r1", true);
	}

	public abstract Type ModulusType { get; }

	public abstract string Curve { get; }

	public abstract bool IsOrder { get; }

	internal abstract int LimbCount { get; }

	internal abstract int ByteLength { get; }

	internal abstract int BitLength { get; }

	internal abstract ulong[] ModulusLimbs { get; }

	internal abstract ulong[] MontgomeryOneLimbs { get; }

	internal abstract ulong[] RSquaredLimbs { get; }

	internal abstract ulong NegativeInverse { get; }

	internal abstract int StorageSize { get; }

	internal abstract int ElementSize { get; }

	internal abstract BigInteger Modulus { get; }

	internal BigInteger R => BigInteger.One << 64 * LimbCount;

	internal abstract BigInteger Add(BigInteger left, BigInteger right, ResultAliasing aliasing = ResultAliasing.None);

	internal abstract BigInteger Multiply(BigInteger left, BigInteger right, ResultAliasing aliasing = ResultAliasing.None);

	internal abstract BigInteger ToMontgomery(BigInteger value, bool inPlace = false);

	internal abstract BigInteger Invert(BigInteger value, bool inPlace = false);

	internal abstract BigInteger InvertVariableTime(BigInteger value, bool inPlace = false);

	internal abstract ulong IsZero(BigInteger value);

	// The result is what Export writes after the import.
	internal abstract bool TryImport(byte[] source, out BigInteger result);

	internal abstract BigInteger ImportReduced(byte[] source);

	internal abstract byte[] Export(BigInteger value);

	internal abstract BigInteger Reduce(BigInteger product);

	internal byte[] Encode(BigInteger value)
	{
		return CurveCase.EncodeInteger(value, ByteLength);
	}

	internal static BigInteger Decode(ReadOnlySpan<byte> bytes)
	{
		return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
	}

	internal BigInteger[] BoundaryValues()
	{
		BigInteger m = Modulus;
		int topShift = 64 * (LimbCount - 1);
		SortedSet<BigInteger> values = [0, 1, 2, 3, m - 3, m - 2, m - 1, m >> 1, (m >> 1) + 1, R % m, FromLimbs(RSquaredLimbs), (m >> topShift << topShift) - 1];

		for (int k = 1; k < LimbCount; ++k)
		{
			BigInteger power = BigInteger.One << 64 * k;
			values.UnionWith([power - 1, power, power + 1, m - power - 1, m - power, m - power + 1]);
		}

		for (int i = 0; i < LimbCount; ++i)
		{
			values.UnionWith([(BigInteger)ulong.MaxValue << 64 * i, BigInteger.One << 64 * i + 63]);
		}

		values.UnionWith([(BigInteger.One << BitLength - 1) - 1, BigInteger.One << BitLength - 1]);
		values.RemoveWhere(value => value < 0 || value >= m);
		return [.. values];
	}

	// bound may be up to 2^(8·ByteLength).
	internal BigInteger RandomBelow(Random random, BigInteger bound)
	{
		byte[] bytes = new byte[ByteLength];
		BigInteger mask = (BigInteger.One << (int)bound.GetBitLength()) - 1;

		while (true)
		{
			random.NextBytes(bytes);
			BigInteger value = Decode(bytes) & mask;

			if (value < bound)
			{
				return value;
			}
		}
	}

	// Limbs that are mostly 0, 1, 2^63, 2^64 − 2 or 2^64 − 1 make long carry and borrow chains.
	internal BigInteger PatternedValue(Random random)
	{
		BigInteger mask = (BigInteger.One << BitLength) - 1;
		Span<byte> bytes = stackalloc byte[sizeof(ulong)];

		while (true)
		{
			BigInteger value = 0;

			for (int i = 0; i < LimbCount; ++i)
			{
				int pattern = random.Next(LimbPatterns.Length + 1);
				random.NextBytes(bytes);
				ulong limb = pattern < LimbPatterns.Length ? LimbPatterns[pattern] : BinaryPrimitives.ReadUInt64LittleEndian(bytes);
				value = value << 64 | limb;
			}

			value &= mask;

			if (value < Modulus)
			{
				return value;
			}
		}
	}

	internal static BigInteger FromLimbs(ReadOnlySpan<ulong> limbs)
	{
		BigInteger value = 0;

		for (int i = limbs.Length - 1; i >= 0; --i)
		{
			value = value << 64 | limbs[i];
		}

		return value;
	}

	public override string ToString()
	{
		return ModulusType.Name;
	}

	private sealed class Case<TModulus>(string curve, bool isOrder) : ModulusCase where TModulus : struct, IMontgomeryModulus
	{
		private delegate void Binary(in FieldElement<TModulus> left, in FieldElement<TModulus> right, out FieldElement<TModulus> result);

		private delegate void Unary(in FieldElement<TModulus> value, out FieldElement<TModulus> result);

		public override Type ModulusType => typeof(TModulus);

		public override string Curve => curve;

		public override bool IsOrder => isOrder;

		internal override int LimbCount => TModulus.LimbCount;

		internal override int ByteLength => TModulus.ByteLength;

		internal override int BitLength => TModulus.BitLength;

		internal override ulong[] ModulusLimbs => TModulus.Modulus.ToArray();

		internal override ulong[] MontgomeryOneLimbs => TModulus.MontgomeryOne.ToArray();

		internal override ulong[] RSquaredLimbs => TModulus.RSquared.ToArray();

		internal override ulong NegativeInverse => TModulus.NegativeInverse;

		internal override int StorageSize => Unsafe.SizeOf<TModulus>();

		internal override int ElementSize => Unsafe.SizeOf<FieldElement<TModulus>>();

		internal override BigInteger Modulus { get; } = FromLimbs(TModulus.Modulus);

		internal override BigInteger Add(BigInteger left, BigInteger right, ResultAliasing aliasing = ResultAliasing.None)
		{
			return Run(FieldElement<TModulus>.Add, left, right, aliasing);
		}

		internal override BigInteger Multiply(BigInteger left, BigInteger right, ResultAliasing aliasing = ResultAliasing.None)
		{
			return Run(FieldElement<TModulus>.Multiply, left, right, aliasing);
		}

		internal override BigInteger ToMontgomery(BigInteger value, bool inPlace = false)
		{
			return Run(FieldElement<TModulus>.ToMontgomery, value, inPlace);
		}

		internal override BigInteger Invert(BigInteger value, bool inPlace = false)
		{
			return Run(FieldElement<TModulus>.Invert, value, inPlace);
		}

		internal override BigInteger InvertVariableTime(BigInteger value, bool inPlace = false)
		{
			return Run(FieldElement<TModulus>.InvertVariableTime, value, inPlace);
		}

		internal override ulong IsZero(BigInteger value)
		{
			return FieldElement<TModulus>.IsZero(ToElement(value));
		}

		internal override bool TryImport(byte[] source, out BigInteger result)
		{
			bool imported = FieldElement<TModulus>.TryImport(source, out FieldElement<TModulus> element);
			result = ToValue(element);
			return imported;
		}

		internal override BigInteger ImportReduced(byte[] source)
		{
			FieldElement<TModulus>.ImportReduced(source, out FieldElement<TModulus> element);
			return ToValue(element);
		}

		internal override byte[] Export(BigInteger value)
		{
			byte[] destination = new byte[ByteLength];
			FieldElement<TModulus>.Export(ToElement(value), destination);
			return destination;
		}

		internal override BigInteger Reduce(BigInteger product)
		{
			int n = TModulus.LimbCount;
			ulong[] limbs = new ulong[2 * n];

			for (int i = 0; i < limbs.Length; ++i)
			{
				limbs[i] = (ulong)(product >> 64 * i & ulong.MaxValue);
			}

			ulong carry = FieldElement<TModulus>.MontgomeryReduce(ref limbs[0]);
			return FromLimbs(limbs.AsSpan(n)) + ((BigInteger)carry << 64 * n);
		}

		private static BigInteger Run(Binary operation, BigInteger left, BigInteger right, ResultAliasing aliasing)
		{
			FieldElement<TModulus> x = ToElement(left);
			FieldElement<TModulus> y = ToElement(right);

			switch (aliasing)
			{
				case ResultAliasing.Left:
					operation(in x, in y, out x);
					return ToValue(x);
				case ResultAliasing.Right:
					operation(in x, in y, out y);
					return ToValue(y);
				default:
					operation(in x, in y, out FieldElement<TModulus> result);
					return ToValue(result);
			}
		}

		private static BigInteger Run(Unary operation, BigInteger value, bool inPlace)
		{
			FieldElement<TModulus> x = ToElement(value);

			if (inPlace)
			{
				operation(in x, out x);
				return ToValue(x);
			}

			operation(in x, out FieldElement<TModulus> result);
			return ToValue(result);
		}

		private static FieldElement<TModulus> ToElement(BigInteger value)
		{
			if (!FieldElement<TModulus>.TryImport(CurveCase.EncodeInteger(value, TModulus.ByteLength), out FieldElement<TModulus> element))
			{
				throw new ArgumentOutOfRangeException(nameof(value), value, "The value is not below the modulus.");
			}

			return element;
		}

		private static BigInteger ToValue(in FieldElement<TModulus> element)
		{
			byte[] bytes = new byte[TModulus.ByteLength];
			FieldElement<TModulus>.Export(in element, bytes);
			return Decode(bytes);
		}
	}
}
