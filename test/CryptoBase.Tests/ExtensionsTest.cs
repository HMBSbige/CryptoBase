using System.Buffers.Binary;

namespace CryptoBase.Tests;

public class ExtensionsTest
{
	[Theory]
	[InlineData(uint.MaxValue)]
	[InlineData(uint.MinValue)]
	[InlineData(255U)]
	[InlineData(65535U)]
	[InlineData(16711935U)]
	[InlineData(1U)]
	[InlineData(114514U)]
	public void FixedTimeIncrementTest(uint i)
	{
		const int size = sizeof(int);
		Span<byte> a = new byte[size];
		Span<byte> b = new byte[size];

		BinaryPrimitives.WriteUInt32LittleEndian(a, i);
		BinaryPrimitives.WriteUInt32LittleEndian(b, i + 1);

		a.FixedTimeIncrement();

		Assert.True(a.SequenceEqual(b));
	}

	[Theory]
	[InlineData(0)]
	[InlineData(255)]
	[InlineData(65535)]
	[InlineData(16711935)]
	[InlineData(1)]
	[InlineData(-1)]
	[InlineData(int.MaxValue)]
	[InlineData(int.MinValue)]
	[InlineData(114514)]
	public void FixedTimeIncrementBigEndianTest(int i)
	{
		const int size = sizeof(int);
		Span<byte> a = new byte[size];
		Span<byte> b = new byte[size];

		BinaryPrimitives.WriteInt32BigEndian(a, i);
		BinaryPrimitives.WriteInt32BigEndian(b, i + 1);

		a.FixedTimeIncrementBigEndian();

		Assert.True(a.SequenceEqual(b));
	}

	[Theory]
	[InlineData(@"", 5381)]
	[InlineData(@"abc", -1549454715)]
	[InlineData(@"abcde", 511372036)]
	[InlineData(@"abcdez", -308130818)]
	[InlineData(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab4", -237686059)]
	[InlineData(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab41a0d", 678771057)]
	[InlineData(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", -1951733499)]
	[InlineData(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", -1610044155)]
	public void GetDeterministicHashCodeTest(string str, int hash)
	{
		Assert.Equal(hash, str.GetDeterministicHashCode());
	}
}
