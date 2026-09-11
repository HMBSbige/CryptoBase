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
}
