using CryptoBase;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Buffers.Binary;
using System.Linq;

namespace UnitTest
{
	[TestClass]
	public class UnitTest
	{
		[TestMethod]
		[DataRow(0)]
		[DataRow(1)]
		[DataRow(-1)]
		[DataRow(int.MaxValue)]
		[DataRow(int.MinValue)]
		[DataRow(114514)]
		public void SodiumIncrementTest(int i)
		{
			const int size = sizeof(int);
			var a = new byte[size];
			var b = new byte[size];

			BinaryPrimitives.WriteInt32LittleEndian(a, i);
			BinaryPrimitives.WriteInt32LittleEndian(b, i + 1);

			a.Increment();

			Assert.IsTrue(a.SequenceEqual(b));
		}

		[TestMethod]
		[DataRow(0)]
		[DataRow(1)]
		[DataRow(-1)]
		[DataRow(int.MaxValue)]
		[DataRow(int.MinValue)]
		[DataRow(114514)]
		public void SodiumIncrementBeTest(int i)
		{
			const int size = sizeof(int);
			var a = new byte[size];
			var b = new byte[size];

			BinaryPrimitives.WriteInt32BigEndian(a, i);
			BinaryPrimitives.WriteInt32BigEndian(b, i + 1);

			a.IncrementBe();

			Assert.IsTrue(a.SequenceEqual(b));
		}
	}
}
