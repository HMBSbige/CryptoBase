using System.Buffers.Binary;

namespace CryptoBase.Tests;

[TestClass]
public class ExtensionsTest
{
	[TestMethod]
	[DataRow(uint.MaxValue)]
	[DataRow(uint.MinValue)]
	[DataRow(255U)]
	[DataRow(65535U)]
	[DataRow(16711935U)]
	[DataRow(1U)]
	[DataRow(114514U)]
	public void FixedTimeIncrementTest(uint i)
	{
		const int size = sizeof(int);
		Span<byte> a = new byte[size];
		Span<byte> b = new byte[size];

		BinaryPrimitives.WriteUInt32LittleEndian(a, i);
		BinaryPrimitives.WriteUInt32LittleEndian(b, i + 1);

		a.FixedTimeIncrement();

		Assert.IsTrue(a.SequenceEqual(b));
	}

	[TestMethod]
	[DataRow(0)]
	[DataRow(255)]
	[DataRow(65535)]
	[DataRow(16711935)]
	[DataRow(1)]
	[DataRow(-1)]
	[DataRow(int.MaxValue)]
	[DataRow(int.MinValue)]
	[DataRow(114514)]
	public void FixedTimeIncrementBigEndianTest(int i)
	{
		const int size = sizeof(int);
		Span<byte> a = new byte[size];
		Span<byte> b = new byte[size];

		BinaryPrimitives.WriteInt32BigEndian(a, i);
		BinaryPrimitives.WriteInt32BigEndian(b, i + 1);

		a.FixedTimeIncrementBigEndian();

		Assert.IsTrue(a.SequenceEqual(b));
	}

	[TestMethod]
	[DataRow(@"", 5381)]
	[DataRow(@"abc", -1549454715)]
	[DataRow(@"abcde", 511372036)]
	[DataRow(@"abcdez", -308130818)]
	[DataRow(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab4", -237686059)]
	[DataRow(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab41a0d", 678771057)]
	[DataRow(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", -1951733499)]
	[DataRow(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", -1610044155)]
	public void GetDeterministicHashCodeTest(string str, int hash)
	{
		Assert.AreEqual(hash, str.GetDeterministicHashCode());
	}
}
