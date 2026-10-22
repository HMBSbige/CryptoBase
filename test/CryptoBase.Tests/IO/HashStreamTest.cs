using CryptoBase.Hashes.Blake3;
using CryptoBase.IO;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.IO.StreamTestUtils;
using static CryptoBase.Tests.TestUtils;
using Sha256Hasher = CryptoBase.Hashes.HashAlgorithm<CryptoBase.Hashes.Sha2.Sha256HashAlgorithm>;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HashStreamTest
{
	[Test]
	[MatrixDataSource]
	public async Task ReadHashesExactlyTheBytesRead([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(81920 + 257);
		byte[] expected = SHA256.HashData(source);
		using YieldingMemoryStream inner = new(source, 3001);
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create());

		byte[] output = await ReadInChunksAsync(hashing, useAsync);

		byte[] actual = new byte[Sha256Hasher.HashLength];
		int written = hashing.GetHashAndReset(actual);

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(expected.Length);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(output).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task WriteHashesAndForwardsTheBytesWritten([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(81920 + 257);
		byte[] expected = SHA256.HashData(source);
		using YieldingMemoryStream inner = new();
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create(), true);

		await WriteInChunksAsync(hashing, source, useAsync);

		byte[] actual = new byte[Sha256Hasher.HashLength];
		hashing.GetCurrentHash(actual);

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CopyToHashesWhenSource([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(200000 + 3);
		byte[] expected = SHA256.HashData(source);
		using MemoryStream inner = new(source, false);
		using MemoryStream destination = new();
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create());

		await CopyToAsync(hashing, destination, useAsync);

		byte[] actual = new byte[Sha256Hasher.HashLength];
		hashing.GetCurrentHash(actual);

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(destination.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CopyToHashesWhenDestination([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(200000 + 3);
		byte[] expected = new byte[Blake3HashAlgorithm.HashLength];
		Blake3HashAlgorithm.HashData(source, expected);
		using MemoryStream input = new(source, false);
		using MemoryStream inner = new();
		using HashStream<Blake3HashAlgorithm> hashing = HashStream.Create(inner, Blake3HashAlgorithm.Create(), true);

		await CopyToAsync(input, hashing, useAsync);

		byte[] actual = new byte[Blake3HashAlgorithm.HashLength];
		hashing.GetCurrentHash(actual);

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task ReadByteAndWriteByteHashEachByte()
	{
		byte[] source = CreateDeterministicSource(37);
		byte[] expected = SHA256.HashData(source);
		using MemoryStream readInner = new(source, false);
		using HashStream<Sha256Hasher> reader = HashStream.Create(readInner, Sha256Hasher.Create());
		using MemoryStream writeInner = new();
		using HashStream<Sha256Hasher> writer = HashStream.Create(writeInner, Sha256Hasher.Create(), true);
		int value;

		while ((value = reader.ReadByte()) >= 0)
		{
			writer.WriteByte((byte)value);
		}

		byte[] readHash = new byte[Sha256Hasher.HashLength];
		byte[] writeHash = new byte[Sha256Hasher.HashLength];
		reader.GetCurrentHash(readHash);
		writer.GetCurrentHash(writeHash);

		using (Assert.Multiple())
		{
			await Assert.That(reader.ReadByte()).IsEqualTo(-1);
			await Assert.That(readHash).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeHash).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeInner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ArrayOverloadsHonorOffsetAndCount([Matrix] bool useAsync)
	{
		const int offset = 5;
		byte[] source = CreateDeterministicSource(301);
		byte[] expected = SHA256.HashData(source);
		using MemoryStream readInner = new(source, false);
		using HashStream<Sha256Hasher> reader = HashStream.Create(readInner, Sha256Hasher.Create());
		byte[] buffer = CreateGuardedBuffer(offset, source.Length);

		int read = useAsync
			? await reader.ReadAsync(buffer, offset, source.Length)
			: reader.Read(buffer, offset, source.Length);

		using MemoryStream writeInner = new();
		using HashStream<Sha256Hasher> writer = HashStream.Create(writeInner, Sha256Hasher.Create(), true);

		await WriteAsync(writer, buffer, offset, read, useAsync);

		byte[] readHash = new byte[Sha256Hasher.HashLength];
		byte[] writeHash = new byte[Sha256Hasher.HashLength];
		reader.GetCurrentHash(readHash);
		writer.GetCurrentHash(writeHash);

		using (Assert.Multiple())
		{
			await Assert.That(read).IsEqualTo(source.Length);
			await AssertOutput(buffer, offset, source);
			await Assert.That(readHash).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeHash).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(writeInner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
			await Assert.That(() => reader.Read(buffer, buffer.Length - 1, 2)).Throws<ArgumentException>();
			await Assert.That(() => writer.Write(null!, 0, 0)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => reader.ReadAsync(buffer, -1, 1)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => writer.WriteAsync(buffer, 0, buffer.Length + 1)).Throws<ArgumentException>();
		}
	}

	[Test]
	public async Task GetCurrentHashReflectsPrefixWithoutChangingState()
	{
		byte[] source = CreateDeterministicSource(1000);
		using MemoryStream inner = new();
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create());
		byte[] prefixHash = new byte[Sha256Hasher.HashLength];
		byte[] fullHash = new byte[Sha256Hasher.HashLength];

		hashing.Write(source.AsSpan(0, 333));
		hashing.GetCurrentHash(prefixHash);
		hashing.Write(source.AsSpan(333));
		hashing.GetCurrentHash(fullHash);

		using (Assert.Multiple())
		{
			await Assert.That(prefixHash).IsEquivalentTo(SHA256.HashData(source.AsSpan(0, 333)), CollectionOrdering.Matching);
			await Assert.That(fullHash).IsEquivalentTo(SHA256.HashData(source), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task GetHashAndResetAndResetStartANewHash()
	{
		byte[] source = CreateDeterministicSource(1000);
		using MemoryStream inner = new();
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create());
		byte[] firstHash = new byte[Sha256Hasher.HashLength];
		byte[] secondHash = new byte[Sha256Hasher.HashLength];
		byte[] thirdHash = new byte[Sha256Hasher.HashLength];

		hashing.Write(source.AsSpan(0, 400));
		hashing.GetHashAndReset(firstHash);
		hashing.Write(source.AsSpan(400, 300));
		hashing.GetCurrentHash(secondHash);
		hashing.Reset();
		hashing.Write(source.AsSpan(700));
		hashing.GetCurrentHash(thirdHash);

		using (Assert.Multiple())
		{
			await Assert.That(firstHash).IsEquivalentTo(SHA256.HashData(source.AsSpan(0, 400)), CollectionOrdering.Matching);
			await Assert.That(secondHash).IsEquivalentTo(SHA256.HashData(source.AsSpan(400, 300)), CollectionOrdering.Matching);
			await Assert.That(thirdHash).IsEquivalentTo(SHA256.HashData(source.AsSpan(700)), CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task PreSeededHasherHashesHeaderThenBody()
	{
		byte[] header = CreateDeterministicSource(19);
		byte[] body = CreateDeterministicSource(4097);
		byte[] expected = SHA256.HashData(Concat(header, body));
		Sha256Hasher hasher = Sha256Hasher.Create();
		hasher.Append(header);
		using MemoryStream inner = new(body, false);
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, hasher);

		hashing.CopyTo(Stream.Null);

		byte[] actual = new byte[Sha256Hasher.HashLength];
		hashing.GetCurrentHash(actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task SeekingIsNotSupported()
	{
		using MemoryStream inner = new();
		using HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create());

		using (Assert.Multiple())
		{
			await Assert.That(hashing.CanSeek).IsFalse();
			await Assert.That(hashing.CanRead).IsTrue();
			await Assert.That(hashing.CanWrite).IsTrue();
			await Assert.That(() => hashing.Length).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => hashing.Position).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => { hashing.Position = 0; }).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => hashing.Seek(0, SeekOrigin.Begin)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => hashing.SetLength(0)).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task CapabilitiesMirrorInnerStream()
	{
		using MemoryStream readOnly = new([1, 2, 3], false);
		using HashStream<Sha256Hasher> hashing = HashStream.Create(readOnly, Sha256Hasher.Create());

		using (Assert.Multiple())
		{
			await Assert.That(hashing.CanRead).IsTrue();
			await Assert.That(hashing.CanWrite).IsFalse();
			await Assert.That(() => hashing.Write([1])).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposeHonorsLeaveOpenAndDisposesHasher([Matrix] bool leaveOpen, [Matrix] bool useAsync)
	{
		using MemoryStream inner = new();
		Sha256Hasher hasher = Sha256Hasher.Create();
		HashStream<Sha256Hasher> hashing = HashStream.Create(inner, hasher, leaveOpen);

		await DisposeAsync(hashing, useAsync);
		await DisposeAsync(hashing, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.CanRead).IsEqualTo(leaveOpen);
			await Assert.That(hashing.CanRead).IsFalse();
			await Assert.That(hashing.CanWrite).IsFalse();
			await Assert.That(() => hasher.Append([1])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task OperationsAfterDisposeThrow()
	{
		using MemoryStream inner = new([1, 2, 3], true);
		HashStream<Sha256Hasher> hashing = HashStream.Create(inner, Sha256Hasher.Create(), true);
		hashing.Dispose();
		byte[] buffer = new byte[Sha256Hasher.HashLength];

		using (Assert.Multiple())
		{
			await Assert.That(() => hashing.Read(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.Read(buffer, 0, 1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.ReadAsync(buffer.AsMemory()).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(hashing.ReadByte).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.Write(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.WriteAsync(buffer.AsMemory()).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.WriteByte(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(hashing.Flush).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(hashing.FlushAsync).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.GetCurrentHash(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hashing.GetHashAndReset(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(hashing.Reset).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(inner.Position).IsZero();
		}
	}

	[Test]
	public async Task ConstructorRejectsNullArguments()
	{
		using MemoryStream inner = new();
		using Sha256Hasher hasher = Sha256Hasher.Create();

		using (Assert.Multiple())
		{
			await Assert.That(() => HashStream.Create(null!, hasher)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => HashStream.Create<Sha256Hasher>(inner, null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("hasher");
			await Assert.That(() => new HashStream<Sha256Hasher>(null!, hasher)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => new HashStream<Sha256Hasher>(inner, null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("hasher");
			await Assert.That(inner.CanRead).IsTrue();
		}
	}
}
