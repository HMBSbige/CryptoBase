using CryptoBase.Ciphers.Padding;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Ciphers;

public class SymmetricPaddingTest
{
	[Test]
	[Arguments(PaddingMode.None, "", "")]
	[Arguments(PaddingMode.None, "0102030405060708", "0102030405060708")]
	[Arguments(PaddingMode.Zeros, "", "")]
	[Arguments(PaddingMode.Zeros, "0102030405060708", "0102030405060708")]
	[Arguments(PaddingMode.Zeros, "010203", "0102030000000000")]
	[Arguments(PaddingMode.PKCS7, "", "0808080808080808")]
	[Arguments(PaddingMode.PKCS7, "010203", "0102030505050505")]
	[Arguments(PaddingMode.PKCS7, "0102030405060708", "01020304050607080808080808080808")]
	[Arguments(PaddingMode.ANSIX923, "", "0000000000000008")]
	[Arguments(PaddingMode.ANSIX923, "010203", "0102030000000005")]
	[Arguments(PaddingMode.ANSIX923, "0102030405060708", "01020304050607080000000000000008")]
	public async Task KnownPaddingBytes(PaddingMode mode, string sourceHex, string expectedHex)
	{
		byte[] source = Convert.FromHexString(sourceHex);
		byte[] expected = Convert.FromHexString(expectedHex);
		byte[] output = new byte[expected.Length + 3];
		output.AsSpan().Fill(0xCC);

		int size = SymmetricPadding.GetPaddedLength(source.Length, 8, mode);
		int written = SymmetricPadding.Pad(source, output, 8, mode);
		bool valid = SymmetricPadding.TryGetUnpaddedLength(output.AsSpan(0, written), 8, mode, out int retained);

		await Assert.That(size).IsEqualTo(expected.Length);
		await Assert.That(written).IsEqualTo(expected.Length);
		await Assert.That(output.AsMemory(0, written)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(output.AsMemory(written)).All(static value => value is 0xCC);
		await Assert.That(valid).IsTrue();
		await Assert.That(retained).IsEqualTo(mode is PaddingMode.Zeros ? expected.Length : source.Length);
	}

	[Test]
	[MatrixDataSource]
	[MatrixExclusion(PaddingMode.None, 1)]
	[MatrixExclusion(PaddingMode.None, 15)]
	[MatrixExclusion(PaddingMode.None, 17)]
	public async Task InteroperatesWithBclPadding
	(
		[Matrix(PaddingMode.None, PaddingMode.Zeros, PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.ISO10126)] PaddingMode mode,
		[Matrix(0, 1, 15, 16, 17, 32)] int length
	)
	{
		using Aes aes = Aes.Create();
		aes.Key = new byte[16];
		byte[] source = new byte[length];

		for (int i = 0; i < length; ++i)
		{
			source[i] = (byte)i;
		}

		int paddedLength = SymmetricPadding.GetPaddedLength(length, 16, mode);
		byte[] padded = new byte[paddedLength];
		SymmetricPadding.Pad(source, padded, 16, mode);
		byte[] encrypted = aes.EncryptEcb(padded, PaddingMode.None);
		byte[] bclPlaintext = aes.DecryptEcb(encrypted, mode);
		byte[] bclCiphertext = aes.EncryptEcb(source, mode);
		byte[] bclPadded = aes.DecryptEcb(bclCiphertext, PaddingMode.None);
		byte[] originalPadded = (byte[])bclPadded.Clone();
		bool valid = SymmetricPadding.TryGetUnpaddedLength(bclPadded, 16, mode, out int retained);

		await Assert.That(paddedLength).IsEqualTo(aes.GetCiphertextLengthEcb(length, mode));
		await Assert.That(valid).IsTrue();
		await Assert.That(retained).IsEqualTo(bclPlaintext.Length);
		await Assert.That(bclPadded).IsEquivalentTo(originalPadded, CollectionOrdering.Matching);
		await Assert.That(bclPadded.AsMemory(0, retained)).IsEquivalentTo(bclPlaintext, CollectionOrdering.Matching);
		await Assert.That(bclPlaintext.AsMemory(0, length)).IsEquivalentTo(source, CollectionOrdering.Matching);

		if (mode is not PaddingMode.ISO10126)
		{
			await Assert.That(padded).IsEquivalentTo(bclPadded, CollectionOrdering.Matching);
		}
	}

	[Test]
	[Arguments(PaddingMode.None)]
	[Arguments(PaddingMode.Zeros)]
	[Arguments(PaddingMode.PKCS7)]
	[Arguments(PaddingMode.ANSIX923)]
	[Arguments(PaddingMode.ISO10126)]
	public async Task SupportsInPlaceAndPreservesUnusedTail(PaddingMode mode)
	{
		byte[] buffer = new byte[40];
		buffer.AsSpan().Fill(0xC5);
		int inputLength = mode is PaddingMode.None ? 16 : 17;
		byte[] original = buffer.AsSpan(0, inputLength).ToArray();
		int written = SymmetricPadding.Pad(buffer.AsSpan(0, inputLength), buffer, 16, mode);

		await Assert.That(buffer.AsMemory(0, inputLength)).IsEquivalentTo(original, CollectionOrdering.Matching);
		await Assert.That(buffer.AsMemory(written)).All(static value => value is 0xC5);
		bool valid = SymmetricPadding.TryGetUnpaddedLength(buffer.AsSpan(0, written), 16, mode, out int retained);
		await Assert.That(valid).IsTrue();
		await Assert.That(retained).IsEqualTo(mode is PaddingMode.Zeros ? written : inputLength);
	}

	[Test]
	[Arguments(-9)]
	[Arguments(-1)]
	[Arguments(1)]
	public async Task RejectsPartialOverlapBeforeWriting(int offset)
	{
		byte[] buffer = new byte[40];
		buffer.AsSpan().Fill(0xD3);
		await Assert.That(() => SymmetricPadding.Pad(buffer.AsSpan(10, 9), buffer.AsSpan(10 + offset, 16), 16, PaddingMode.PKCS7))
			.ThrowsExactly<ArgumentException>();
		await Assert.That(buffer).All(static value => value is 0xD3);
	}

	[Test]
	public async Task AllowsSourceInsideUnusedDestinationTail()
	{
		byte[] buffer = new byte[32];
		buffer.AsSpan().Fill(0xA7);
		Convert.FromHexString("010203").CopyTo(buffer, 24);
		byte[] originalTail = buffer.AsSpan(16).ToArray();
		int written = SymmetricPadding.Pad(buffer.AsSpan(24, 3), buffer, 16, PaddingMode.PKCS7);
		await Assert.That(written).IsEqualTo(16);
		await Assert.That(buffer.AsMemory(16)).IsEquivalentTo(originalTail, CollectionOrdering.Matching);
		await Assert.That(buffer.AsMemory(0, written)).IsEquivalentTo(Convert.FromHexString("0102030D0D0D0D0D0D0D0D0D0D0D0D0D"), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(16, 16, PaddingMode.PKCS7)]
	[Arguments(15, 15, PaddingMode.PKCS7)]
	[Arguments(3, 16, PaddingMode.None)]
	public async Task ArgumentFailuresDoNotWrite(int sourceLength, int destinationLength, PaddingMode mode)
	{
		byte[] destination = new byte[16];
		destination.AsSpan().Fill(0xB6);

		await Assert.That(() => SymmetricPadding.Pad(new byte[sourceLength], destination.AsSpan(0, destinationLength), 16, mode)).ThrowsExactly<ArgumentException>();
		await Assert.That(destination).All(static value => value is 0xB6);
	}

	[Test]
	[Arguments(0)]
	[Arguments(256)]
	public async Task InvalidBlockSizesDoNotWrite(int blockSize)
	{
		byte[] destination = new byte[16];
		destination.AsSpan().Fill(0xB6);

		await Assert.That(() => SymmetricPadding.Pad(new byte[3], destination, blockSize, PaddingMode.PKCS7)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is 0xB6);
		await Assert.That(() => SymmetricPadding.TryGetUnpaddedLength(destination, blockSize, PaddingMode.PKCS7, out _)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is 0xB6);
	}

	[Test]
	[Arguments((PaddingMode)0)]
	[Arguments((PaddingMode)6)]
	public async Task InvalidPaddingModesDoNotWrite(PaddingMode mode)
	{
		byte[] destination = new byte[16];
		destination.AsSpan().Fill(0xB6);

		await Assert.That(() => SymmetricPadding.Pad(new byte[3], destination, 16, mode)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is 0xB6);
		await Assert.That(() => SymmetricPadding.TryGetUnpaddedLength(destination, 16, mode, out _)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is 0xB6);
	}

	[Test]
	public async Task LengthArithmeticDoesNotOverflowPrematurely()
	{
		await Assert.That(SymmetricPadding.GetPaddedLength(int.MaxValue - 2, 7, PaddingMode.PKCS7)).IsEqualTo(int.MaxValue - 1);
		await Assert.That(SymmetricPadding.GetPaddedLength(int.MaxValue, 1, PaddingMode.None)).IsEqualTo(int.MaxValue);
		await Assert.That(SymmetricPadding.GetPaddedLength(int.MaxValue, 1, PaddingMode.Zeros)).IsEqualTo(int.MaxValue);
		await Assert.That(() => SymmetricPadding.GetPaddedLength(int.MaxValue, 1, PaddingMode.PKCS7)).ThrowsExactly<OverflowException>();
		await Assert.That(() => SymmetricPadding.GetPaddedLength(int.MaxValue, 16, PaddingMode.PKCS7)).ThrowsExactly<OverflowException>();
		await Assert.That(() => SymmetricPadding.GetPaddedLength(-1, 16, PaddingMode.PKCS7)).ThrowsExactly<ArgumentOutOfRangeException>();
	}

	[Test]
	[MatrixDataSource]
	public async Task RejectsEveryCorruptedPaddingByte([Matrix(PaddingMode.PKCS7, PaddingMode.ANSIX923)] PaddingMode mode, [MatrixRange<int>(1, 16)] int count)
	{
		// Construct the expected encoding independently of Pad, then corrupt every checked position.
		byte[] padded = new byte[32];
		padded.AsSpan().Fill(0x9D);
		padded.AsSpan(32 - count, count - 1).Fill(mode is PaddingMode.PKCS7 ? (byte)count : (byte)0);
		padded[31] = (byte)count;
		bool valid = SymmetricPadding.TryGetUnpaddedLength(padded, 16, mode, out int retained);
		await Assert.That(valid).IsTrue();
		await Assert.That(retained).IsEqualTo(32 - count);

		for (int i = 32 - count; i < 32; ++i)
		{
			byte[] corrupted = (byte[])padded.Clone();
			corrupted[i] = i is 31 ? (byte)0 : (byte)(corrupted[i] ^ 0x80);
			await AssertRejectedWithoutMutation(corrupted, mode);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task RejectsMalformedLengths([Matrix(PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.ISO10126)] PaddingMode mode, [Matrix(0, 15, 17)] int size)
	{
		byte[] data = new byte[size];
		data.AsSpan().Fill(0xA5);

		if (size is not 0)
		{
			data[size - 1] = 1;
		}

		await AssertRejectedWithoutMutation(data, mode);
	}

	[Test]
	[MatrixDataSource]
	public async Task RejectsInvalidPaddingCounts([Matrix(PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.ISO10126)] PaddingMode mode, [Matrix(0, 17, 128, 255)] int count)
	{
		byte[] data = new byte[32];
		data.AsSpan().Fill(mode is PaddingMode.ANSIX923 ? (byte)0 : (byte)count);
		data[31] = (byte)count;

		await AssertRejectedWithoutMutation(data, mode);
	}

	[Test]
	[MatrixDataSource]
	public async Task AlignmentIsCheckedWithoutInferringZeroPadding([Matrix(PaddingMode.None, PaddingMode.Zeros)] PaddingMode mode, [Matrix(15, 16, 17)] int size)
	{
		bool valid = SymmetricPadding.TryGetUnpaddedLength(new byte[size], 16, mode, out int retained);

		await Assert.That(valid).IsEqualTo(size is 16);
		await Assert.That(retained).IsEqualTo(size is 16 ? size : 0);
	}

	[Test]
	[MatrixDataSource]
	public async Task Iso10126AcceptsArbitraryPaddingContents([MatrixRange<int>(1, 16)] int count)
	{
		byte[] padded = Convert.FromHexString("FF0002F0800473A901FE237E815AC3B6");
		padded[15] = (byte)count;
		byte[] original = (byte[])padded.Clone();
		bool accepted = SymmetricPadding.TryGetUnpaddedLength(padded, 16, PaddingMode.ISO10126, out int length);

		await Assert.That(accepted).IsTrue();
		await Assert.That(length).IsEqualTo(16 - count);
		await Assert.That(padded).IsEquivalentTo(original, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task SupportsBlockSizeBoundaries([Matrix(PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.ISO10126)] PaddingMode mode, [Matrix(1, 255)] int blockSize)
	{
		byte[] expected = new byte[blockSize];
		expected.AsSpan().Fill
		(
			mode switch
			{
				PaddingMode.PKCS7 => (byte)blockSize,
				PaddingMode.ANSIX923 => 0,
				_ => 0xA5
			}
		);
		expected[blockSize - 1] = (byte)blockSize;
		byte[] original = (byte[])expected.Clone();
		byte[] output = new byte[blockSize];
		output.AsSpan().Fill(0xCC);
		int written = SymmetricPadding.Pad([], output, blockSize, mode);

		await Assert.That(SymmetricPadding.GetPaddedLength(0, blockSize, mode)).IsEqualTo(blockSize);
		await Assert.That(written).IsEqualTo(blockSize);
		await Assert.That(output[blockSize - 1]).IsEqualTo((byte)blockSize);

		if (mode is not PaddingMode.ISO10126)
		{
			await Assert.That(output).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}

		bool valid = SymmetricPadding.TryGetUnpaddedLength(expected, blockSize, mode, out int retained);
		await Assert.That(valid).IsTrue();
		await Assert.That(retained).IsEqualTo(0);
		await Assert.That(expected).IsEquivalentTo(original, CollectionOrdering.Matching);
	}

	private static async Task AssertRejectedWithoutMutation(byte[] data, PaddingMode mode)
	{
		byte[] original = (byte[])data.Clone();
		bool accepted = SymmetricPadding.TryGetUnpaddedLength(data, 16, mode, out int length);

		await Assert.That(accepted).IsFalse();
		await Assert.That(length).IsEqualTo(0);
		await Assert.That(data).IsEquivalentTo(original, CollectionOrdering.Matching);
	}
}
