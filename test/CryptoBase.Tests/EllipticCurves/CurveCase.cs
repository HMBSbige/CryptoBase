using CryptoBase.EllipticCurves;
using CryptoBase.Tests.Wycheproof;
using System.Numerics;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.EllipticCurves;

// Points go in and come out with plain coordinates, scalars as plain values.
public abstract class CurveCase
{
	private protected CurveCase(string name)
	{
		Name = name;
		Parameters = WycheproofVectors.Load<EcCurveTestVector>("ec_prime_order_curves_test.json").Single(curve => curve.Name == name);
		Reference = new EcReference(Parameters);
	}

	public static IEnumerable<CurveCase> All()
	{
		yield return new Case<P256Curve, P256Field52, P256Order>("secp256r1");
		yield return new Case<P384Curve, P384Field56, P384Order>("secp384r1");
		yield return new Case<P521Curve, P521Field58, P521Order>("secp521r1");
	}

	public static CurveCase Named(string name)
	{
		return All().Single(curve => curve.Name == name);
	}

	public abstract Type CurveType { get; }

	public abstract Type FieldType { get; }

	public string Name { get; }

	internal EcCurveTestVector Parameters { get; }

	internal EcReference Reference { get; }

	internal BigInteger Order => Reference.N;

	internal abstract int FieldLength { get; }

	internal abstract int ScalarLength { get; }

	internal abstract int ScalarBitLength { get; }

	internal abstract BigInteger FieldModulus { get; }

	internal abstract BigInteger OrderModulus { get; }

	// The range of the 64-bit limbs of a scalar.
	internal BigInteger ScalarLimbRange => BigInteger.One << 64 * ScalarLimbCount;

	internal abstract int ScalarLimbCount { get; }

	// The constants as stored, plain.
	internal abstract BigInteger StoredB { get; }

	internal abstract BigInteger StoredGeneratorX { get; }

	internal abstract BigInteger StoredGeneratorY { get; }

	internal abstract int GeneratorWindowWidth { get; }

	internal abstract int GeneratorWindowCount { get; }

	internal abstract int GeneratorWindowLength { get; }

	internal int PublicKeyLength => 1 + 2 * FieldLength;

	internal abstract JacobianValue Add(JacobianValue left, CurvePoint right, bool inPlace = false);

	// The sum and the mask that tells equal points.
	internal abstract (JacobianValue Sum, ulong Equal) AddDistinct(JacobianValue left, JacobianValue right, ResultAliasing aliasing = ResultAliasing.None);

	internal abstract (JacobianValue Sum, ulong Equal) AddDistinct(JacobianValue left, CurvePoint right, bool inPlace = false);

	internal abstract JacobianValue Double(JacobianValue value, bool inPlace = false);

	internal abstract JacobianValue MultiplyBase(BigInteger scalar);

	internal abstract JacobianValue Multiply(CurvePoint point, BigInteger scalar);

	internal abstract CurvePoint MultiplyBaseToAffine(BigInteger scalar);

	internal abstract BigInteger MultiplyBaseReduceX(BigInteger scalar);

	internal abstract bool TryMultiplyExportX(CurvePoint point, BigInteger scalar, byte[] destination);

	internal abstract (byte[] Encoded, byte[] X) MultiplyEncodeExportX(CurvePoint point, BigInteger scalar);

	internal abstract CurvePoint ToAffine(JacobianValue value);

	internal abstract byte[] ExportX(JacobianValue value);

	internal abstract BigInteger ReduceX(JacobianValue value);

	// The result is what FieldElement<TOrder>.TryImportNonzero leaves, whether or not it accepts.
	internal abstract bool TryImportScalar(byte[] source, out BigInteger scalar);

	internal abstract byte[] Encode(CurvePoint point);

	// The result is what TryDecode leaves, whether or not it accepts.
	internal abstract bool TryDecode(byte[] source, out CurvePoint point);

	internal abstract CurvePoint[] GeneratorTable();

	internal abstract CurvePoint SelectFromGeneratorTable(int window, int digit);

	// The multiples need not be points.
	internal abstract CurvePoint SelectFromMultiples(CurvePoint[] multiples, int digit);

	// The table of k·P: 1·P to count·P.
	internal abstract CurvePoint[] Multiples(CurvePoint point, int count);

	// The table of the one-off u1·G + u2·Q: Q, 3Q, ….
	internal abstract CurvePoint[] OddMultiplesVariableTime(CurvePoint point, int count);

	internal abstract int VariableTimeGeneratorWidth { get; }

	internal abstract CurvePoint[] VariableTimeGeneratorTable();

	internal abstract JacobianValue MultiplyAddVariableTime(BigInteger u1, CurvePoint point, BigInteger u2);

	internal abstract int PointTableWidth { get; }

	internal abstract int PointTablePartCount { get; }

	internal abstract int PointTablePartLength { get; }

	internal abstract CurvePoint[] VariableTimePointTable(CurvePoint point);

	// With the table of point.
	internal abstract JacobianValue MultiplyAddWithTableVariableTime(BigInteger u1, CurvePoint point, BigInteger u2);

	internal abstract bool XModOrderEqualsVariableTime(JacobianValue point, BigInteger r);

	internal abstract JacobianValue AddVariableTime(JacobianValue left, CurvePoint right, bool inPlace = false);

	internal abstract int RecodeVariableTime(BigInteger scalar, int width, out int[] digits);

	internal abstract int RecodeVariableTime(BigInteger scalar, int start, int length, int width, out int[] digits);

	internal abstract KeyCase NewKey();

	internal byte[] EncodeScalar(BigInteger value)
	{
		return EncodeInteger(value, ScalarLength);
	}

	internal byte[] EncodeCoordinate(BigInteger value)
	{
		return EncodeInteger(value, FieldLength);
	}

	// Written here rather than by the code under test.
	internal byte[] EncodePoint(CurvePoint point)
	{
		return [0x04, .. EncodeCoordinate(point.X), .. EncodeCoordinate(point.Y)];
	}

	// Reads an uncompressed point without checking it.
	internal CurvePoint DecodePoint(ReadOnlySpan<byte> encoding)
	{
		return new CurvePoint(ModulusCase.Decode(encoding.Slice(1, FieldLength)), ModulusCase.Decode(encoding.Slice(1 + FieldLength)));
	}

	internal static byte[] EncodeInteger(BigInteger value, int length)
	{
		byte[] bytes = new byte[length];
		int count = value.GetByteCount(isUnsigned: true);

		if (value.Sign < 0 || count > length || !value.TryWriteBytes(bytes.AsSpan(length - count), out _, isUnsigned: true, isBigEndian: true))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, $"The value does not fit in {length} bytes.");
		}

		return bytes;
	}

	public override string ToString()
	{
		return Name;
	}

	private sealed class Case<TCurve, TField, TOrder>(string name) : CurveCase(name)
		where TCurve : struct, IEcCurve
		where TField : unmanaged, IEcField<TField>
		where TOrder : unmanaged, IMontgomeryModulus
	{
		public override Type CurveType => typeof(TCurve);

		public override Type FieldType => typeof(TField);

		internal override int FieldLength => TField.ByteLength;

		internal override int ScalarLength => TOrder.ByteLength;

		internal override int ScalarBitLength => TOrder.BitLength;

		internal override BigInteger FieldModulus => ModulusCase.FromLimbs(TField.Modulus);

		internal override BigInteger OrderModulus => ModulusCase.FromLimbs(TOrder.Modulus);

		internal override int ScalarLimbCount => TOrder.LimbCount;

		internal override BigInteger StoredB => ModulusCase.FromLimbs(TCurve.B);

		internal override BigInteger StoredGeneratorX => ModulusCase.FromLimbs(TCurve.GeneratorX);

		internal override BigInteger StoredGeneratorY => ModulusCase.FromLimbs(TCurve.GeneratorY);

		internal override int GeneratorWindowWidth => TCurve.GeneratorWindowWidth;

		internal override int GeneratorWindowCount => EcGeneratorTable<TCurve, TField, TOrder>.WindowCount;

		internal override int GeneratorWindowLength => EcGeneratorTable<TCurve, TField, TOrder>.WindowLength;

		internal override JacobianValue Add(JacobianValue left, CurvePoint right, bool inPlace = false)
		{
			JacobianPoint<TField> x = ToPoint(left);
			AffinePoint<TField> y = ToPoint(right);

			if (inPlace)
			{
				EcGroup<TCurve, TField, TOrder>.Add(in x, in y, out x);
				return ToValue(x);
			}

			EcGroup<TCurve, TField, TOrder>.Add(in x, in y, out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override (JacobianValue Sum, ulong Equal) AddDistinct(JacobianValue left, JacobianValue right, ResultAliasing aliasing = ResultAliasing.None)
		{
			JacobianPoint<TField> x = ToPoint(left);
			JacobianPoint<TField> y = ToPoint(right);
			ulong equal;

			switch (aliasing)
			{
				case ResultAliasing.Left:
					equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in y, out x);
					return (ToValue(x), equal);
				case ResultAliasing.Right:
					equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in y, out y);
					return (ToValue(y), equal);
				default:
					equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in y, out JacobianPoint<TField> result);
					return (ToValue(result), equal);
			}
		}

		internal override (JacobianValue Sum, ulong Equal) AddDistinct(JacobianValue left, CurvePoint right, bool inPlace = false)
		{
			JacobianPoint<TField> x = ToPoint(left);
			AffinePoint<TField> y = ToPoint(right);
			ulong equal;

			if (inPlace)
			{
				equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in y, out x);
				return (ToValue(x), equal);
			}

			equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in y, out JacobianPoint<TField> result);
			return (ToValue(result), equal);
		}

		internal override JacobianValue Double(JacobianValue value, bool inPlace = false)
		{
			JacobianPoint<TField> x = ToPoint(value);

			if (inPlace)
			{
				EcGroup<TCurve, TField, TOrder>.Double(in x, out x);
				return ToValue(x);
			}

			EcGroup<TCurve, TField, TOrder>.Double(in x, out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override JacobianValue MultiplyBase(BigInteger scalar)
		{
			EcGroup<TCurve, TField, TOrder>.MultiplyBase(ToScalar(scalar), out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override JacobianValue Multiply(CurvePoint point, BigInteger scalar)
		{
			EcGroup<TCurve, TField, TOrder>.Multiply(ToPoint(point), ToScalar(scalar), out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override CurvePoint MultiplyBaseToAffine(BigInteger scalar)
		{
			EcGroup<TCurve, TField, TOrder>.MultiplyBaseToAffine(ToScalar(scalar), out AffinePoint<TField> result);
			return ToValue(result);
		}

		internal override BigInteger MultiplyBaseReduceX(BigInteger scalar)
		{
			EcGroup<TCurve, TField, TOrder>.MultiplyBaseReduceX(ToScalar(scalar), out FieldElement<TOrder> result);
			return ScalarValue(result);
		}

		internal override bool TryMultiplyExportX(CurvePoint point, BigInteger scalar, byte[] destination)
		{
			return EcGroup<TCurve, TField, TOrder>.TryMultiplyExportX(ToPoint(point), ToScalar(scalar), destination);
		}

		internal override (byte[] Encoded, byte[] X) MultiplyEncodeExportX(CurvePoint point, BigInteger scalar)
		{
			byte[] encoded = new byte[EcGroup<TCurve, TField, TOrder>.EncodedLength];
			byte[] x = new byte[TField.ByteLength];
			EcGroup<TCurve, TField, TOrder>.MultiplyEncodeExportX(ToPoint(point), ToScalar(scalar), encoded, x);
			return (encoded, x);
		}

		internal override CurvePoint ToAffine(JacobianValue value)
		{
			EcGroup<TCurve, TField, TOrder>.ToAffine(ToPoint(value), out AffinePoint<TField> result);
			return ToValue(result);
		}

		internal override byte[] ExportX(JacobianValue value)
		{
			byte[] x = new byte[TField.ByteLength];
			EcGroup<TCurve, TField, TOrder>.ExportX(ToPoint(value), x);
			return x;
		}

		internal override BigInteger ReduceX(JacobianValue value)
		{
			EcGroup<TCurve, TField, TOrder>.ReduceX(ToPoint(value), out FieldElement<TOrder> result);
			return ScalarValue(result);
		}

		internal override bool TryImportScalar(byte[] source, out BigInteger scalar)
		{
			bool imported = FieldElement<TOrder>.TryImportNonzero(source, out FieldElement<TOrder> result);
			scalar = ScalarValue(result);
			return imported;
		}

		internal override byte[] Encode(CurvePoint point)
		{
			byte[] encoding = new byte[EcGroup<TCurve, TField, TOrder>.EncodedLength];
			EcGroup<TCurve, TField, TOrder>.Encode(ToPoint(point), encoding);
			return encoding;
		}

		internal override bool TryDecode(byte[] source, out CurvePoint point)
		{
			bool decoded = EcGroup<TCurve, TField, TOrder>.TryDecode(source, out AffinePoint<TField> result);
			point = ToValue(result);
			return decoded;
		}

		internal override CurvePoint[] GeneratorTable()
		{
			CurvePoint[] table = new CurvePoint[EcGeneratorTable<TCurve, TField, TOrder>.WindowCount * EcGeneratorTable<TCurve, TField, TOrder>.WindowLength];

			for (int i = 0; i < table.Length; ++i)
			{
				EcGeneratorTable<TCurve, TField, TOrder>.Read(i, out AffinePoint<TField> entry);
				table[i] = ToValue(entry);
			}

			return table;
		}

		internal override CurvePoint SelectFromGeneratorTable(int window, int digit)
		{
			EcGroup<TCurve, TField, TOrder>.SelectBase(window, digit, out AffinePoint<TField> result);
			return ToValue(result);
		}

		internal override CurvePoint SelectFromMultiples(CurvePoint[] multiples, int digit)
		{
			AffinePoint<TField>[] points = [.. multiples.Select(static multiple => ToPoint(multiple))];
			EcGroup<TCurve, TField, TOrder>.Select(points, digit, out AffinePoint<TField> result);
			return ToValue(result);
		}

		internal override CurvePoint[] Multiples(CurvePoint point, int count)
		{
			AffinePoint<TField>[] multiples = new AffinePoint<TField>[count];
			EcGroup<TCurve, TField, TOrder>.BuildMultiples(ToPoint(point), multiples);
			return [.. multiples.Select(static multiple => ToValue(multiple))];
		}

		internal override CurvePoint[] OddMultiplesVariableTime(CurvePoint point, int count)
		{
			AffinePoint<TField>[] multiples = new AffinePoint<TField>[count];
			EcVariableTimeGroup<TCurve, TField, TOrder>.BuildOddMultiples(ToPoint(point), multiples);
			return [.. multiples.Select(static multiple => ToValue(multiple))];
		}

		internal override int VariableTimeGeneratorWidth => EcVariableTimeGeneratorTable<TCurve, TField, TOrder>.Width;

		internal override CurvePoint[] VariableTimeGeneratorTable()
		{
			return [.. EcVariableTimeGeneratorTable<TCurve, TField, TOrder>.Entries.Select(static entry => ToValue(entry))];
		}

		internal override JacobianValue MultiplyAddVariableTime(BigInteger u1, CurvePoint point, BigInteger u2)
		{
			EcVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(ToScalar(u1), ToPoint(point), ToScalar(u2), out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override int PointTableWidth => EcVariableTimePointTable<TCurve, TField, TOrder>.Width;

		internal override int PointTablePartCount => EcVariableTimePointTable<TCurve, TField, TOrder>.PartCount;

		internal override int PointTablePartLength => EcVariableTimePointTable<TCurve, TField, TOrder>.PartLength;

		internal override CurvePoint[] VariableTimePointTable(CurvePoint point)
		{
			return [.. EcVariableTimePointTable<TCurve, TField, TOrder>.Build(ToPoint(point)).Select(static entry => ToValue(entry))];
		}

		internal override JacobianValue MultiplyAddWithTableVariableTime(BigInteger u1, CurvePoint point, BigInteger u2)
		{
			AffinePoint<TField>[] table = EcVariableTimePointTable<TCurve, TField, TOrder>.Build(ToPoint(point));
			EcVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(ToScalar(u1), table, ToScalar(u2), out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override bool XModOrderEqualsVariableTime(JacobianValue point, BigInteger r)
		{
			return EcVariableTimeGroup<TCurve, TField, TOrder>.XModOrderEquals(ToPoint(point), ToScalar(r));
		}

		internal override JacobianValue AddVariableTime(JacobianValue left, CurvePoint right, bool inPlace = false)
		{
			JacobianPoint<TField> x = ToPoint(left);
			AffinePoint<TField> y = ToPoint(right);

			if (inPlace)
			{
				EcVariableTimeGroup<TCurve, TField, TOrder>.Add(in x, in y, out x);
				return ToValue(x);
			}

			EcVariableTimeGroup<TCurve, TField, TOrder>.Add(in x, in y, out JacobianPoint<TField> result);
			return ToValue(result);
		}

		internal override int RecodeVariableTime(BigInteger scalar, int width, out int[] digits)
		{
			sbyte[] recoded = new sbyte[EcVariableTimeGroup<TCurve, TField, TOrder>.DigitCount];
			int top = EcVariableTimeGroup<TCurve, TField, TOrder>.Recode(ToScalar(scalar), width, recoded);
			digits = [.. recoded.Select(static digit => (int)digit)];
			return top;
		}

		internal override int RecodeVariableTime(BigInteger scalar, int start, int length, int width, out int[] digits)
		{
			sbyte[] recoded = new sbyte[length + 1];
			int top = EcVariableTimeGroup<TCurve, TField, TOrder>.Recode(ToScalar(scalar), start, length, width, recoded);
			digits = [.. recoded.Select(static digit => (int)digit)];
			return top;
		}

		internal override KeyCase NewKey()
		{
			return new Key();
		}

		private static TField ToElement(BigInteger value)
		{
			if (!TField.TryImport(EncodeInteger(value, TField.ByteLength), out TField element))
			{
				throw new ArgumentOutOfRangeException(nameof(value), value, "The value is not below p.");
			}

			TField.ToMontgomery(in element, out element);
			return element;
		}

		private static BigInteger FieldValue(in TField element)
		{
			TField.FromMontgomery(in element, out TField plain);
			byte[] bytes = new byte[TField.ByteLength];
			TField.Export(in plain, bytes);
			return ModulusCase.Decode(bytes);
		}

		private static FieldElement<TOrder> ToScalar(BigInteger value)
		{
			if (!FieldElement<TOrder>.TryImport(EncodeInteger(value, TOrder.ByteLength), out FieldElement<TOrder> scalar))
			{
				throw new ArgumentOutOfRangeException(nameof(value), value, "The scalar is not below n.");
			}

			return scalar;
		}

		private static BigInteger ScalarValue(in FieldElement<TOrder> scalar)
		{
			byte[] bytes = new byte[TOrder.ByteLength];
			FieldElement<TOrder>.Export(in scalar, bytes);
			return ModulusCase.Decode(bytes);
		}

		private static AffinePoint<TField> ToPoint(CurvePoint point)
		{
			return new AffinePoint<TField> { X = ToElement(point.X), Y = ToElement(point.Y) };
		}

		private static CurvePoint ToValue(in AffinePoint<TField> point)
		{
			return new CurvePoint(FieldValue(point.X), FieldValue(point.Y));
		}

		private static JacobianPoint<TField> ToPoint(JacobianValue value)
		{
			return new JacobianPoint<TField> { X = ToElement(value.X), Y = ToElement(value.Y), Z = ToElement(value.Z) };
		}

		private static JacobianValue ToValue(in JacobianPoint<TField> point)
		{
			return new JacobianValue(FieldValue(point.X), FieldValue(point.Y), FieldValue(point.Z));
		}

		private sealed class Key : KeyCase
		{
			private EcKey<TCurve, TField, TOrder> _key;

			internal override bool HasPrivateKey => _key.HasPrivateKey;

			internal override bool HasPublicKey => _key.HasPublicKey;

			internal override BigInteger PrivateScalar => ScalarValue(_key.PrivateScalar);

			internal override CurvePoint PublicPoint => ToValue(_key.PublicPoint);

			internal override int PrivateKeyLength => EcKey<TCurve, TField, TOrder>.PrivateKeyLength;

			internal override int PublicKeyLength => EcKey<TCurve, TField, TOrder>.PublicKeyLength;

			internal override int SharedSecretLength => EcKey<TCurve, TField, TOrder>.SharedSecretLength;

			internal override void GenerateKey()
			{
				_key.GenerateKey();
			}

			internal override void GenerateKey(Action<Span<byte>> fill)
			{
				_key.GenerateKey(fill);
			}

			internal override bool TryImportPrivateKey(byte[] source)
			{
				return _key.TryImportPrivateKey(source);
			}

			internal override bool TryImportPublicKey(byte[] source)
			{
				return _key.TryImportPublicKey(source);
			}

			internal override int ExportPrivateKey(byte[] destination)
			{
				return _key.ExportPrivateKey(destination);
			}

			internal override int ExportPublicKey(byte[] destination)
			{
				return _key.ExportPublicKey(destination);
			}

			internal override bool TryDeriveSharedSecret(byte[] peerPublicKey, byte[] destination)
			{
				return _key.TryDeriveSharedSecret(peerPublicKey, destination);
			}

			internal override void Clear()
			{
				_key.Clear();
			}

			internal override byte[] Storage()
			{
				return MemoryMarshal.AsBytes(new ReadOnlySpan<EcKey<TCurve, TField, TOrder>>(ref _key)).ToArray();
			}
		}
	}
}
