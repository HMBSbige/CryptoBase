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
		uint[] lanes = [0x03020100u, 0x07060504u, 0x0B0A0908u, 0x0F0E0D0Cu, 0x13121110u, 0x17161514u, 0x1B1A1918u, 0x1F1E1D1Cu];
		Vector256<uint> source = Vector256.Create(lanes);
		Vector256<uint> expected = Vector256.Create(lanes.Select(lane => BitOperations.RotateRight(lane, offset)).ToArray());

#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		Vector256<uint> actual = source.RotateRightUInt32(offset);
#pragma warning restore CA1857

		await Assert.That(actual).IsEqualTo(expected);
	}

	[Test]
	[Arguments((byte)1)]
	[Arguments((byte)7)]
	[Arguments((byte)8)]
	[Arguments((byte)12)]
	[Arguments((byte)16)]
	[Arguments((byte)24)]
	[Arguments((byte)31)]
	public async Task ShouldRotateRightUInt32Vector128(byte offset)
	{
		uint[] lanes = [0x83020100u, 0x07060504u, 0x0B0A0908u, 0xFF0E0D0Cu];
		Vector128<uint> source = Vector128.Create(lanes);
		Vector128<uint> expected = Vector128.Create(lanes.Select(lane => BitOperations.RotateRight(lane, offset)).ToArray());

#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		Vector128<uint> actual = source.RotateRightUInt32(offset);
#pragma warning restore CA1857

		await Assert.That(actual).IsEqualTo(expected);
	}

	[Test]
	[Arguments((byte)1)]
	[Arguments((byte)8)]
	[Arguments((byte)16)]
	[Arguments((byte)24)]
	[Arguments((byte)32)]
	[Arguments((byte)40)]
	[Arguments((byte)48)]
	[Arguments((byte)56)]
	public async Task ShouldRotateRightUInt64(byte offset)
	{
		ulong[] lanes = [0x0706050403020100UL, 0x0F0E0D0C0B0A0908UL, 0x1716151413121110UL, 0x1F1E1D1C1B1A1918UL];
		Vector256<ulong> source = Vector256.Create(lanes);
		Vector256<ulong> expected = Vector256.Create(lanes.Select(lane => BitOperations.RotateRight(lane, offset)).ToArray());

#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		Vector256<ulong> actual = source.RotateRightUInt64(offset);
#pragma warning restore CA1857

		await Assert.That(actual).IsEqualTo(expected);
	}
}
