using System.Runtime.Intrinsics;

namespace CryptoBase.Tests.Vectors;

public class VectorMemoryExtensionsTest
{
	[Test]
	public async Task LoadPartialUnsafeZeroesEveryByteAfterTheLength()
	{
		byte[] source = new byte[3 + 16 + 3];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i + 1);
		}

		for (int offset = 0; offset <= 3; ++offset)
		{
			for (int length = 1; length <= 16; ++length)
			{
				byte[] expected = new byte[16];
				source.AsSpan(offset, length).CopyTo(expected);

				Vector128<byte> actual = Vector128.LoadPartialUnsafe(ref source[0], (nuint)offset, length);

				await Assert.That(actual).IsEqualTo(Vector128.Create(expected));
			}
		}
	}
}
