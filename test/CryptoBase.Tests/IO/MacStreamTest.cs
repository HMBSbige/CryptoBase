using CryptoBase.IO;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.IO.StreamTestUtils;
using static CryptoBase.Tests.TestUtils;
using HmacSha256 = CryptoBase.Macs.Hmac.HmacAlgorithm<CryptoBase.Hashes.Sha256.Sha256HashAlgorithm>;
using HmacSha512 = CryptoBase.Macs.Hmac.HmacAlgorithm<CryptoBase.Hashes.Sha512.Sha512HashAlgorithm>;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class MacStreamTest
{
	// Longer than the SHA-256 block size, so HMAC hashes the key first.
	private static readonly byte[] Key = CreateDeterministicSource(97);

	[Test]
	[MatrixDataSource]
	public async Task ReadAuthenticatesExactlyTheBytesRead([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(81920 + 257);
		byte[] expected = HMACSHA256.HashData(Key, source);
		using YieldingMemoryStream inner = new(source, 3001);
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key));

		byte[] output = await ReadInChunksAsync(authenticating, useAsync);

		byte[] actual = new byte[HmacSha256.MacLength];
		int written = authenticating.GetMacAndReset(actual);

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(expected.Length);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(output).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task WriteAuthenticatesAndForwardsTheBytesWritten([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(81920 + 257);
		byte[] expected = HMACSHA256.HashData(Key, source);
		using YieldingMemoryStream inner = new();
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key), true);

		await WriteInChunksAsync(authenticating, source, useAsync);

		byte[] actual = new byte[HmacSha256.MacLength];
		authenticating.GetCurrentMac(actual);

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CopyToAuthenticatesWhenSource([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(200000 + 3);
		byte[] expected = HMACSHA256.HashData(Key, source);
		using MemoryStream inner = new(source, false);
		using MemoryStream destination = new();
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key));

		await CopyToAsync(authenticating, destination, useAsync);

		byte[] actual = new byte[HmacSha256.MacLength];
		authenticating.GetCurrentMac(actual);

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(destination.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CopyToAuthenticatesWhenDestination([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(200000 + 3);
		byte[] expected = HMACSHA512.HashData(Key, source);
		using MemoryStream input = new(source, false);
		using MemoryStream inner = new();
		using MacStream<HmacSha512> authenticating = MacStream.Create(inner, HmacSha512.Create(Key), true);

		await CopyToAsync(input, authenticating, useAsync);

		byte[] actual = new byte[HmacSha512.MacLength];
		authenticating.GetCurrentMac(actual);

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task ReadByteAndWriteByteAuthenticateEachByte()
	{
		byte[] source = CreateDeterministicSource(37);
		byte[] expected = HMACSHA256.HashData(Key, source);
		using MemoryStream readInner = new(source, false);
		using MacStream<HmacSha256> reader = MacStream.Create(readInner, HmacSha256.Create(Key));
		using MemoryStream writeInner = new();
		using MacStream<HmacSha256> writer = MacStream.Create(writeInner, HmacSha256.Create(Key), true);
		int value;

		while ((value = reader.ReadByte()) >= 0)
		{
			writer.WriteByte((byte)value);
		}

		byte[] readMac = new byte[HmacSha256.MacLength];
		byte[] writeMac = new byte[HmacSha256.MacLength];
		reader.GetCurrentMac(readMac);
		writer.GetCurrentMac(writeMac);

		using (Assert.Multiple())
		{
			await Assert.That(reader.ReadByte()).IsEqualTo(-1);
			await Assert.That(readMac).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeMac).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeInner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ArrayOverloadsHonorOffsetAndCount([Matrix] bool useAsync)
	{
		const int offset = 5;
		byte[] source = CreateDeterministicSource(301);
		byte[] expected = HMACSHA256.HashData(Key, source);
		using MemoryStream readInner = new(source, false);
		using MacStream<HmacSha256> reader = MacStream.Create(readInner, HmacSha256.Create(Key));
		byte[] buffer = CreateGuardedBuffer(offset, source.Length);

		int read = useAsync
			? await reader.ReadAsync(buffer, offset, source.Length)
			: reader.Read(buffer, offset, source.Length);

		using MemoryStream writeInner = new();
		using MacStream<HmacSha256> writer = MacStream.Create(writeInner, HmacSha256.Create(Key), true);

		await WriteAsync(writer, buffer, offset, read, useAsync);

		byte[] readMac = new byte[HmacSha256.MacLength];
		byte[] writeMac = new byte[HmacSha256.MacLength];
		reader.GetCurrentMac(readMac);
		writer.GetCurrentMac(writeMac);

		using (Assert.Multiple())
		{
			await Assert.That(read).IsEqualTo(source.Length);
			await AssertOutput(buffer, offset, source);
			await Assert.That(readMac).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeMac).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeInner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
			await Assert.That(() => reader.Read(buffer, buffer.Length - 1, 2)).Throws<ArgumentException>();
			await Assert.That(() => writer.Write(null!, 0, 0)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => reader.ReadAsync(buffer, -1, 1)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => writer.WriteAsync(buffer, 0, buffer.Length + 1)).Throws<ArgumentException>();
		}
	}

	[Test]
	public async Task GetCurrentMacReflectsPrefixWithoutChangingState()
	{
		byte[] source = CreateDeterministicSource(1000);
		using MemoryStream inner = new();
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key));
		byte[] prefixMac = new byte[HmacSha256.MacLength];
		byte[] fullMac = new byte[HmacSha256.MacLength];

		authenticating.Write(source.AsSpan(0, 333));
		authenticating.GetCurrentMac(prefixMac);
		authenticating.Write(source.AsSpan(333));
		authenticating.GetCurrentMac(fullMac);

		using (Assert.Multiple())
		{
			await Assert.That(prefixMac).IsEquivalentTo(HMACSHA256.HashData(Key, source.AsSpan(0, 333)), CollectionOrdering.Matching);
			await Assert.That(fullMac).IsEquivalentTo(HMACSHA256.HashData(Key, source), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task GetMacAndResetAndResetStartANewMacWithTheSameKey()
	{
		byte[] source = CreateDeterministicSource(1000);
		using MemoryStream inner = new();
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key));
		byte[] firstMac = new byte[HmacSha256.MacLength];
		byte[] secondMac = new byte[HmacSha256.MacLength];
		byte[] thirdMac = new byte[HmacSha256.MacLength];

		authenticating.Write(source.AsSpan(0, 400));
		authenticating.GetMacAndReset(firstMac);
		authenticating.Write(source.AsSpan(400, 300));
		authenticating.GetCurrentMac(secondMac);
		authenticating.Reset();
		authenticating.Write(source.AsSpan(700));
		authenticating.GetCurrentMac(thirdMac);

		using (Assert.Multiple())
		{
			await Assert.That(firstMac).IsEquivalentTo(HMACSHA256.HashData(Key, source.AsSpan(0, 400)), CollectionOrdering.Matching);
			await Assert.That(secondMac).IsEquivalentTo(HMACSHA256.HashData(Key, source.AsSpan(400, 300)), CollectionOrdering.Matching);
			await Assert.That(thirdMac).IsEquivalentTo(HMACSHA256.HashData(Key, source.AsSpan(700)), CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task PreSeededMacAuthenticatesHeaderThenBody()
	{
		byte[] header = CreateDeterministicSource(19);
		byte[] body = CreateDeterministicSource(4097);
		byte[] expected = HMACSHA256.HashData(Key, Concat(header, body));
		HmacSha256 mac = HmacSha256.Create(Key);
		mac.Append(header);
		using MemoryStream inner = new(body, false);
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, mac);

		authenticating.CopyTo(Stream.Null);

		byte[] actual = new byte[HmacSha256.MacLength];
		authenticating.GetCurrentMac(actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task SeekingIsNotSupported()
	{
		using MemoryStream inner = new();
		using MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key));

		using (Assert.Multiple())
		{
			await Assert.That(authenticating.CanSeek).IsFalse();
			await Assert.That(authenticating.CanRead).IsTrue();
			await Assert.That(authenticating.CanWrite).IsTrue();
			await Assert.That(() => authenticating.Length).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => authenticating.Position).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => { authenticating.Position = 0; }).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => authenticating.Seek(0, SeekOrigin.Begin)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => authenticating.SetLength(0)).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task CapabilitiesMirrorInnerStream()
	{
		using MemoryStream readOnly = new([1, 2, 3], false);
		using MacStream<HmacSha256> authenticating = MacStream.Create(readOnly, HmacSha256.Create(Key));

		using (Assert.Multiple())
		{
			await Assert.That(authenticating.CanRead).IsTrue();
			await Assert.That(authenticating.CanWrite).IsFalse();
			await Assert.That(() => authenticating.Write([1])).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposeHonorsLeaveOpenAndDisposesMac([Matrix] bool leaveOpen, [Matrix] bool useAsync)
	{
		using MemoryStream inner = new();
		HmacSha256 mac = HmacSha256.Create(Key);
		MacStream<HmacSha256> authenticating = MacStream.Create(inner, mac, leaveOpen);

		await DisposeAsync(authenticating, useAsync);
		await DisposeAsync(authenticating, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.CanRead).IsEqualTo(leaveOpen);
			await Assert.That(authenticating.CanRead).IsFalse();
			await Assert.That(authenticating.CanWrite).IsFalse();
			await Assert.That(() => mac.Append([1])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task OperationsAfterDisposeThrow()
	{
		using MemoryStream inner = new([1, 2, 3], true);
		MacStream<HmacSha256> authenticating = MacStream.Create(inner, HmacSha256.Create(Key), true);
		authenticating.Dispose();
		byte[] buffer = new byte[HmacSha256.MacLength];

		using (Assert.Multiple())
		{
			await Assert.That(() => authenticating.Read(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.Read(buffer, 0, 1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.ReadAsync(buffer.AsMemory()).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(authenticating.ReadByte).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.Write(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.WriteAsync(buffer.AsMemory()).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.WriteByte(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(authenticating.Flush).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(authenticating.FlushAsync).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.GetCurrentMac(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => authenticating.GetMacAndReset(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(authenticating.Reset).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(inner.Position).IsZero();
		}
	}

	[Test]
	public async Task ConstructorRejectsNullArguments()
	{
		using MemoryStream inner = new();
		using HmacSha256 mac = HmacSha256.Create(Key);

		using (Assert.Multiple())
		{
			await Assert.That(() => MacStream.Create(null!, mac)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => MacStream.Create<HmacSha256>(inner, null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("mac");
			await Assert.That(() => new MacStream<HmacSha256>(null!, mac)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => new MacStream<HmacSha256>(inner, null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("mac");
			await Assert.That(inner.CanRead).IsTrue();
		}
	}
}
