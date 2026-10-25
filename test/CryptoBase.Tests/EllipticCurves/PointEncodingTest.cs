using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class PointEncodingTest
{
	private const int RandomCount = 16;

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task EncodeWritesTheUncompressedForm(CurveCase curve)
	{
		List<string> failures = [];

		foreach (CurvePoint point in Points(curve.Reference, new Random(1)))
		{
			if (!curve.Encode(point).AsSpan().SequenceEqual(curve.EncodePoint(point)))
			{
				failures.Add(Show(point));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task DecodeReadsEveryPointOfTheCurve(CurveCase curve)
	{
		List<string> failures = [];

		foreach (CurvePoint point in Points(curve.Reference, new Random(2)))
		{
			if (!curve.TryDecode(curve.EncodePoint(point), out CurvePoint decoded) || decoded != point)
			{
				failures.Add($"{Show(point)} became {Show(decoded)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task DecodeRejectsEverythingElse(CurveCase curve)
	{
		List<string> failures = [];

		foreach ((string name, byte[] encoding) in InvalidEncodings(curve))
		{
			if (curve.TryDecode(encoding, out CurvePoint decoded) || decoded != new CurvePoint(0, 0))
			{
				failures.Add($"{name} became {Show(decoded)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ExportXWritesTheAffineX(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(3);
		List<string> failures = [];

		foreach (CurvePoint point in Points(reference, random))
		{
			if (!curve.ExportX(reference.RandomizeJacobian(point, random)).AsSpan().SequenceEqual(curve.EncodeCoordinate(point.X)))
			{
				failures.Add(Show(point));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ReduceXTakesTheAffineXModN(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(4);
		List<string> failures = [];

		foreach (CurvePoint point in Points(reference, random))
		{
			BigInteger reduced = curve.ReduceX(reference.RandomizeJacobian(point, random));

			if (reduced != point.X % curve.Order)
			{
				failures.Add($"{Show(point)} gave {reduced:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ImportScalarTakesOneToNMinusOne(CurveCase curve)
	{
		BigInteger n = curve.Order;
		int length = curve.ScalarLength;
		Random random = new(5);
		List<string> failures = [];
		List<(string Name, byte[] Source, BigInteger? Expected)> cases = [];

		foreach (BigInteger value in (BigInteger[])[0, 1, 2, n - 2, n - 1, n, n + 1, (BigInteger.One << 8 * length) - 1])
		{
			cases.Add(($"{value:X}", curve.EncodeScalar(value), value > 0 && value < n ? value : null));
		}

		for (int i = 0; i < RandomCount; ++i)
		{
			BigInteger value = 1 + EcReference.RandomBelow(random, n - 1);
			cases.Add(($"{value:X}", curve.EncodeScalar(value), value));
		}

		// Every leading byte above that of n, with 1 below it; there is none where n starts with 0xFF.
		for (int top = (int)(n >> 8 * (length - 1)) + 1; top <= 0xFF; ++top)
		{
			BigInteger value = ((BigInteger)top << 8 * (length - 1)) + 1;
			cases.Add(($"{value:X}", curve.EncodeScalar(value), null));
		}

		foreach (int wrongLength in (int[])[0, 1, length - 1, length + 1, 2 * length])
		{
			byte[] source = new byte[wrongLength];

			if (wrongLength > 0)
			{
				source[^1] = 1;
			}

			cases.Add(($"{wrongLength} bytes", source, null));
		}

		foreach ((string name, byte[] source, BigInteger? expected) in cases)
		{
			if (curve.TryImportScalar(source, out BigInteger scalar) != expected.HasValue || scalar != (expected ?? 0))
			{
				failures.Add($"{name} became {scalar:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The points with the least x and the least y have encodings that start with zero bytes, and the one with the least x from n makes ReduceX reduce.
	private static IEnumerable<CurvePoint> Points(EcReference reference, Random random)
	{
		yield return reference.Generator;
		yield return reference.PointWithXFrom(0);
		yield return reference.PointWithYFrom(0);
		yield return reference.PointWithXFrom(reference.N);

		for (int i = 0; i < RandomCount; ++i)
		{
			CurvePoint point = reference.RandomPoint(random);
			yield return point;
			yield return point with { Y = reference.Mod(-point.Y) };
		}
	}

	private static IEnumerable<(string Name, byte[] Encoding)> InvalidEncodings(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		CurvePoint g = reference.Generator;
		byte[] x = curve.EncodeCoordinate(g.X);
		byte[] y = curve.EncodeCoordinate(g.Y);
		byte[] allOnes = [.. Enumerable.Repeat((byte)0xFF, curve.FieldLength)];
		byte[] encoding = curve.EncodePoint(g);

		yield return ("empty", []);
		yield return ("0x00, the point at infinity", [0x00]);
		yield return ("0x04 ‖ x", [0x04, .. x]);
		yield return ("x ‖ y", [.. x, .. y]);
		yield return ("the encoding with the last byte cut", encoding.AsSpan(0, encoding.Length - 1).ToArray());
		yield return ("the encoding with a byte appended", [.. encoding, 0x00]);
		yield return ("the compressed form", [(byte)(g.Y.IsEven ? 0x02 : 0x03), .. x]);

		foreach (byte prefix in (byte[])[0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0xFF])
		{
			yield return ($"prefix 0x{prefix:X2}", [prefix, .. x, .. y]);
		}

		yield return ("x = p", [0x04, .. curve.EncodeCoordinate(reference.P), .. y]);
		yield return ("y = p", [0x04, .. x, .. curve.EncodeCoordinate(reference.P)]);
		yield return ("x all 0xFF", [0x04, .. allOnes, .. y]);
		yield return ("y all 0xFF", [0x04, .. x, .. allOnes]);

		// G with every leading byte above that of p in either coordinate; there is none where p starts with 0xFF.
		for (int top = (int)(reference.P >> 8 * (curve.FieldLength - 1)) + 1; top <= 0xFF; ++top)
		{
			yield return ($"x with leading byte 0x{top:X2}", [0x04, (byte)top, .. x.AsSpan(1), .. y]);
			yield return ($"y with leading byte 0x{top:X2}", [0x04, .. x, (byte)top, .. y.AsSpan(1)]);
		}

		// Points of the curve with a coordinate written as itself plus p, which the encoding has room for when it is small.
		CurvePoint leastX = reference.PointWithXFrom(0);
		CurvePoint leastY = reference.PointWithYFrom(0);
		yield return ("x + p", [0x04, .. curve.EncodeCoordinate(leastX.X + reference.P), .. curve.EncodeCoordinate(leastX.Y)]);
		yield return ("y + p", [0x04, .. curve.EncodeCoordinate(leastY.X), .. curve.EncodeCoordinate(leastY.Y + reference.P)]);

		yield return ("(x, y + 1)", [0x04, .. x, .. curve.EncodeCoordinate(reference.Mod(g.Y + 1))]);
		yield return ("(0, 0)", [0x04, .. curve.EncodeCoordinate(0), .. curve.EncodeCoordinate(0)]);
	}
}
