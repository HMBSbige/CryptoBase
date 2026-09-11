using System.Numerics;
using System.Runtime.Intrinsics;

namespace CryptoBase.Tests.Vectors;

public class VectorBitOperationsExtensionsTest
{
	[Test]
	[Arguments((byte)8)]
	[Arguments((byte)16)]
	[Arguments((byte)24)]
	public async Task ShouldRotateRightUInt32(byte offset)
	{
		Vector256<uint> source = Vector256.Create(0x03020100u, 0x07060504u, 0x0B0A0908u, 0x0F0E0D0Cu, 0x13121110u, 0x17161514u, 0x1B1A1918u, 0x1F1E1D1Cu);
		Vector256<uint> expected = Vector256.Create
		(
			BitOperations.RotateRight(source.GetElement(0), offset),
			BitOperations.RotateRight(source.GetElement(1), offset),
			BitOperations.RotateRight(source.GetElement(2), offset),
			BitOperations.RotateRight(source.GetElement(3), offset),
			BitOperations.RotateRight(source.GetElement(4), offset),
			BitOperations.RotateRight(source.GetElement(5), offset),
			BitOperations.RotateRight(source.GetElement(6), offset),
			BitOperations.RotateRight(source.GetElement(7), offset)
		);

#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		Vector256<uint> actual = source.RotateRightUInt32(offset);
#pragma warning restore CA1857

		await Assert.That(actual).IsEqualTo(expected);
	}

	[Test]
	[Arguments((byte)8)]
	[Arguments((byte)16)]
	[Arguments((byte)24)]
	[Arguments((byte)32)]
	[Arguments((byte)40)]
	[Arguments((byte)48)]
	[Arguments((byte)56)]
	public async Task ShouldRotateRightUInt64(byte offset)
	{
		Vector256<ulong> source = Vector256.Create(0x0706050403020100UL, 0x0F0E0D0C0B0A0908UL, 0x1716151413121110UL, 0x1F1E1D1C1B1A1918UL);
		Vector256<ulong> expected = Vector256.Create
		(
			BitOperations.RotateRight(source.GetElement(0), offset),
			BitOperations.RotateRight(source.GetElement(1), offset),
			BitOperations.RotateRight(source.GetElement(2), offset),
			BitOperations.RotateRight(source.GetElement(3), offset)
		);

#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		Vector256<ulong> actual = source.RotateRightUInt64(offset);
#pragma warning restore CA1857

		await Assert.That(actual).IsEqualTo(expected);
	}
}
