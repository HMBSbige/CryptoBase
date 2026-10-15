using System.Runtime.Intrinsics;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Vectors;

public class VectorMemoryExtensionsTest
{
	[Test]
	[MatrixDataSource]
	public async Task LoadPartialUnsafeZeroesEveryByteAfterTheLength([Matrix(0, 1, 2, 3)] int offset, [MatrixRange<int>(1, 16)] int length)
	{
		byte[] source = new byte[3 + 16 + 3];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i + 1);
		}

		byte[] expected = new byte[16];
		source.AsSpan(offset, length).CopyTo(expected);

		Vector128<byte> actual = Vector128.LoadPartialUnsafe(ref source[0], (nuint)offset, length);

		await Assert.That(actual).IsEqualTo(Vector128.Create(expected));
	}

	[Test]
	[MatrixDataSource]
	public async Task StorePartialUnsafeWritesOnlyTheLength([Matrix(0, 1, 2, 3)] int offset, [MatrixRange<int>(1, 16)] int length)
	{
		Vector128<byte> value = Vector128.CreateSequence((byte)1, (byte)1);
		byte[] actual = new byte[3 + 16 + 3];
		PrepareDestination(actual);

		value.StorePartialUnsafe(ref actual[0], (nuint)offset, length);

		await AssertOutput(actual, offset, value.AsReadOnlySpan().Slice(0, length).ToArray());
	}
}
