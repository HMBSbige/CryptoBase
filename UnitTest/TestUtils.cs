using CryptoBase;
using CryptoBase.Abstractions.Digests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace UnitTest
{
	public static class TestUtils
	{
		public static void TestFileStream(IHash hash, string path, string str)
		{
			using var stream = File.OpenRead(path);
			Span<byte> outBuffer = new byte[hash.Length];

			stream.Seek(0, SeekOrigin.Begin);
			hash.Update(stream);
			hash.GetHash(outBuffer);
			Assert.AreEqual(str.ToLower(), outBuffer.ToHex());

			stream.Seek(0, SeekOrigin.Begin);
			hash.UpdateFinal(stream, outBuffer);
			Assert.AreEqual(str.ToLower(), outBuffer.ToHex());
		}

		public static async Task TestFileStreamAsync(IHash hash, string path, string str)
		{
			await using var stream = File.OpenRead(path);
			Memory<byte> outBuffer = new byte[hash.Length];

			stream.Seek(0, SeekOrigin.Begin);
			await hash.UpdateAsync(stream);
			hash.GetHash(outBuffer.Span);
			Assert.AreEqual(str.ToLower(), outBuffer.Span.ToHex());

			stream.Seek(0, SeekOrigin.Begin);
			await hash.UpdateFinalAsync(stream, outBuffer);
			Assert.AreEqual(str.ToLower(), outBuffer.Span.ToHex());
		}

		public static async Task TestStreamAsync(IHash hash, string str, string result)
		{
			Memory<byte> origin = Encoding.UTF8.GetBytes(str);
			Memory<byte> outBuffer = new byte[hash.Length];

			var stream = new MemoryStream();
			stream.Write(origin.Span);

			stream.Seek(0, SeekOrigin.Begin);
			hash.Update(stream);
			hash.GetHash(outBuffer.Span);
			Assert.AreEqual(result, outBuffer.Span.ToHex());

			stream.Seek(0, SeekOrigin.Begin);
			hash.UpdateFinal(stream, outBuffer.Span);
			Assert.AreEqual(result, outBuffer.Span.ToHex());

			stream.Seek(0, SeekOrigin.Begin);
			await hash.UpdateAsync(stream);
			hash.GetHash(outBuffer.Span);
			Assert.AreEqual(result, outBuffer.Span.ToHex());

			stream.Seek(0, SeekOrigin.Begin);
			await hash.UpdateFinalAsync(stream, outBuffer);
			Assert.AreEqual(result, outBuffer.Span.ToHex());
		}

		public static void LargeMessageTest(IHash hash, string str, string result)
		{
			Span<byte> origin = Encoding.UTF8.GetBytes(str);
			Span<byte> outBuffer = stackalloc byte[hash.Length];

			var times = (uint)((uint.MaxValue + 10ul) / (double)origin.Length) + 10;

			for (var i = 0; i < times; ++i)
			{
				hash.Update(origin);
			}

			hash.GetHash(outBuffer);

			Assert.AreEqual(result, outBuffer.ToHex());
		}
	}
}
