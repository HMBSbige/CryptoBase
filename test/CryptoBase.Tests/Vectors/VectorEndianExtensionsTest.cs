using System.Runtime.Intrinsics;

namespace CryptoBase.Tests.Vectors;

public class VectorEndianExtensionsTest
{
	[Test]
	public async Task ShouldReverseEndianness()
	{
		Vector128<ulong> source = Vector128.Create(0x0123456789ABCDEFUL, 0x0F1E2D3C4B5A6978UL);

		await Assert.That(source.ReverseEndianness128()).IsEqualTo(Vector128.Create(0x78695A4B3C2D1E0FUL, 0xEFCDAB8967452301UL));
		await Assert.That(source.ReverseEndianness64()).IsEqualTo(Vector128.Create(0xEFCDAB8967452301UL, 0x78695A4B3C2D1E0FUL));
		await Assert.That(source.AsUInt32().ReverseEndianness32()).IsEqualTo(Vector128.Create(0xEFCDAB89u, 0x67452301, 0x78695A4B, 0x3C2D1E0F));
	}

	[Test]
	public async Task ShouldReverseEndianness256()
	{
		Vector256<byte> source = Vector256.CreateSequence((byte)0, (byte)1);

		await Assert.That(source.ReverseEndianness128().AsUInt64()).IsEqualTo(Vector256.Create(0x08090A0B0C0D0E0FUL, 0x0001020304050607UL, 0x18191A1B1C1D1E1FUL, 0x1011121314151617UL));
		await Assert.That(source.ReverseEndianness64().AsUInt64()).IsEqualTo(Vector256.Create(0x0001020304050607UL, 0x08090A0B0C0D0E0FUL, 0x1011121314151617UL, 0x18191A1B1C1D1E1FUL));
		await Assert.That(source.ReverseEndianness32().AsUInt32()).IsEqualTo(Vector256.Create(0x00010203u, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F));
	}

	[Test]
	public async Task ShouldReverseEndianness512()
	{
		Vector512<byte> source = Vector512.CreateSequence((byte)0, (byte)1);
		Vector512<ulong> expected = Vector512.Create
		(
			0x08090A0B0C0D0E0FUL, 0x0001020304050607UL, 0x18191A1B1C1D1E1FUL, 0x1011121314151617UL,
			0x28292A2B2C2D2E2FUL, 0x2021222324252627UL, 0x38393A3B3C3D3E3FUL, 0x3031323334353637UL
		);

		await Assert.That(source.ReverseEndianness128().AsUInt64()).IsEqualTo(expected);
	}
}
