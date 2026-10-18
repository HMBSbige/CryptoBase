using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.IO.XtsTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class DataUnitStreamTest
{
	private const int DefaultDataUnitSize = 512;

	[Test]
	[GenerateGenericTest(typeof(XtsMode<AesCipher>))]
	[GenerateGenericTest(typeof(XtsMode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task FuzzMatchesShadow<TCipher>([Matrix(16, 100, 512, 4096)] int dataUnitSize, [Matrix] bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		using MemoryStream inner = new();
		await using DataUnitStream<TCipher> xts = DataUnitStream.Create(inner, TCipher.Create(Key), dataUnitSize, leaveOpen: true);

		await RunFuzz<TCipher>(new DataUnitStreamTarget(xts, inner.ToArray), new XtsShadow(dataUnitSize, 512 * 1024), 0x5EED + dataUnitSize, 300, useAsync);
	}

	[Test]
	[MatrixDataSource]
	public async Task CiphertextMatchesDataUnitRandomAccess([Matrix(100, 4096)] int dataUnitSize, [Matrix] bool useAsync)
	{
		const int seed = 0x0C1F;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using MemoryStream inner = new();

		using (DataUnitRandomAccess<XtsMode<AesCipher>> randomAccess = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), dataUnitSize, leaveOpen: true))
		{
			await RunFuzz<XtsMode<AesCipher>>(new DataUnitRandomAccessTarget<XtsMode<AesCipher>>(randomAccess, handle), new XtsShadow(dataUnitSize, 256 * 1024), seed, 120, useAsync);
		}

		await using (DataUnitStream<XtsMode<AesCipher>> stream = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), dataUnitSize, leaveOpen: true))
		{
			await RunFuzz<XtsMode<AesCipher>>(new DataUnitStreamTarget(stream, inner.ToArray), new XtsShadow(dataUnitSize, 256 * 1024), seed, 120, useAsync);
		}

		await AssertBytesEqual(inner.ToArray(), ReadAll(handle));
	}

	[Test]
	[GenerateGenericTest(typeof(XtsMode<AesCipher>))]
	[GenerateGenericTest(typeof(XtsMode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task FileStreamBackendMatchesOracle<TCipher>([Matrix] bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		const int unit = 4096;
		UInt128 first = new(1, 0x8000_0000_0000_0000);
		byte[] plaintext = CreateDeterministicSource(20 * unit + 123);
		byte[] padded = PadToDataUnits(plaintext, unit);
		using TempFile file = new();

		await using (FileStream inner = new(file.Path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, useAsync))
		{
			await using DataUnitStream<TCipher> xts = DataUnitStream.Create(inner, TCipher.Create(Key), unit, first);

			if (useAsync)
			{
				await xts.WriteAsync(plaintext);
				await xts.FlushAsync();
			}
			else
			{
				xts.Write(plaintext);
				xts.Flush();
			}

			byte[] actual = new byte[padded.Length + 5];
			PrepareDestination(actual);
			xts.Seek(0, SeekOrigin.Begin);
			int read = useAsync ? await xts.ReadAsync(actual) : xts.Read(actual);

			using (Assert.Multiple())
			{
				await Assert.That(xts.Length).IsEqualTo(padded.Length);
				await Assert.That(read).IsEqualTo(padded.Length);
				await Assert.That(xts.Position).IsEqualTo(padded.Length);
				await AssertOutput(actual, padded);
			}
		}

		await AssertBytesEqual(await File.ReadAllBytesAsync(file.Path), Encrypt<TCipher>(padded, unit, first));
	}

	[Test]
	public async Task PositionSeekAndLengthFollowStreamConventions()
	{
		const int unit = 16;
		using MemoryStream inner = new();
		using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit);
		byte[] data = CreateDeterministicSource(20);
		byte[] buffer = new byte[64];

		using (Assert.Multiple())
		{
			await Assert.That(xts.CanRead).IsTrue();
			await Assert.That(xts.CanWrite).IsTrue();
			await Assert.That(xts.CanSeek).IsTrue();
			await Assert.That(xts.DataUnitSize).IsEqualTo(unit);
			await Assert.That(xts.Position).IsZero();
			await Assert.That(xts.Length).IsZero();
		}

		inner.Position = 7;
		xts.Write(data);

		using (Assert.Multiple())
		{
			await Assert.That(xts.Position).IsEqualTo(20);
			await Assert.That(xts.Length).IsEqualTo(32);
			await Assert.That(xts.Seek(-5, SeekOrigin.Current)).IsEqualTo(15);
			await Assert.That(xts.Read(buffer.AsSpan(0, 3))).IsEqualTo(3);
			await AssertBytesEqual(buffer.AsSpan(0, 3).ToArray(), data.AsSpan(15, 3).ToArray());
			await Assert.That(xts.Position).IsEqualTo(18);
			await Assert.That(xts.Seek(3, SeekOrigin.Begin)).IsEqualTo(3);
			await Assert.That(xts.Seek(-1, SeekOrigin.End)).IsEqualTo(31);
			await Assert.That(xts.Seek(10, SeekOrigin.End)).IsEqualTo(42);
			await Assert.That(xts.Read(buffer)).IsZero();
			await Assert.That(xts.Position).IsEqualTo(42);
		}

		xts.Write(data.AsSpan(0, 1));

		using (Assert.Multiple())
		{
			await Assert.That(xts.Position).IsEqualTo(43);
			await Assert.That(xts.Length).IsEqualTo(48);
			xts.Position = 20;
			await Assert.That(xts.Read(buffer)).IsEqualTo(28);
			await Assert.That(buffer.AsMemory(0, 22)).All(static value => value is 0);
			await Assert.That(buffer[22]).IsEqualTo(data[0]);
			await Assert.That(buffer.AsMemory(23, 5)).All(static value => value is 0);
		}

		xts.SetLength(16);

		using (Assert.Multiple())
		{
			await Assert.That(xts.Position).IsEqualTo(16);
			await Assert.That(xts.Length).IsEqualTo(16);
			await Assert.That(() => xts.Position = -1).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("value");
			await Assert.That(() => xts.Seek(-17, SeekOrigin.End)).ThrowsExactly<IOException>();
			await Assert.That(() => xts.Seek(0, (SeekOrigin)3)).ThrowsExactly<ArgumentException>().WithParameterName("origin");
			await Assert.That(() => xts.SetLength(-1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("value");
			await Assert.That(() => xts.SetLength(17)).ThrowsExactly<ArgumentException>().WithParameterName("value");
			await Assert.That(xts.Position).IsEqualTo(16);
			await Assert.That(xts.Length).IsEqualTo(16);
		}
	}

	[Test]
	public async Task ReadByteAndWriteByteTouchEachDataUnitOnce()
	{
		const int unit = 16;
		byte[] data = CreateDeterministicSource(40);
		byte[] padded = new byte[48];
		data.CopyTo(padded, 0);
		using CountingMemoryStream inner = new();
		using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);

		foreach (byte value in data)
		{
			xts.WriteByte(value);
		}

		using (Assert.Multiple())
		{
			// The third unit is still cached.
			await Assert.That(inner.WriteCount).IsEqualTo(2);
			await Assert.That(inner.Length).IsEqualTo(2 * unit);
			await Assert.That(xts.Length).IsEqualTo(padded.Length);
		}

		xts.Flush();

		using (Assert.Multiple())
		{
			await Assert.That(inner.WriteCount).IsEqualTo(3);
			await Assert.That(inner.ReadCount).IsZero();
			await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<AesCipher>>(padded, unit));
		}

		xts.Position = 0;
		byte[] actual = new byte[padded.Length];

		for (int i = 0; i < actual.Length; ++i)
		{
			int value = xts.ReadByte();
			await Assert.That(value).IsBetween(0, 255);
			actual[i] = (byte)value;
		}

		using (Assert.Multiple())
		{
			await AssertBytesEqual(actual, padded);
			await Assert.That(xts.ReadByte()).IsEqualTo(-1);
			await Assert.That(xts.Position).IsEqualTo(padded.Length);
			await Assert.That(inner.ReadCount).IsEqualTo(3);
			await Assert.That(inner.WriteCount).IsEqualTo(3);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task SmallSequentialTransfersTouchEachDataUnitOnce([Matrix] bool useAsync)
	{
		const int unit = 512;
		const int chunk = 100;
		byte[] data = CreateDeterministicSource(8 * unit + chunk);
		byte[] padded = PadToDataUnits(data, unit);
		using CountingMemoryStream inner = new();
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);

		for (int offset = 0; offset < data.Length; offset += chunk)
		{
			await target.WriteAsync(data, offset, Math.Min(chunk, data.Length - offset), offset, useAsync);
		}

		await FlushAsync(xts, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.WriteCount).IsEqualTo(9);
			await Assert.That(inner.ReadCount).IsZero();
			await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<AesCipher>>(padded, unit));
		}

		byte[] actual = new byte[padded.Length];

		for (int offset = 0; offset < actual.Length; offset += chunk)
		{
			int count = Math.Min(chunk, actual.Length - offset);
			await Assert.That(await target.ReadAsync(actual, offset, count, offset, useAsync)).IsEqualTo(count);
		}

		using (Assert.Multiple())
		{
			await AssertBytesEqual(actual, padded);
			await Assert.That(inner.ReadCount).IsEqualTo(9);
			await Assert.That(inner.WriteCount).IsEqualTo(9);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task AppendAfterPartialDataUnitWritesEachDataUnitOnce([Matrix] bool useAsync)
	{
		const int unit = 512;
		byte[] data = CreateDeterministicSource(5 * unit + 100);
		byte[] padded = PadToDataUnits(data, unit);
		using CountingMemoryStream inner = new();
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);

		// The second write completes the cached head unit, appends whole units and starts a partial tail unit.
		await target.WriteAsync(data, 0, 100, 0, useAsync);
		await target.WriteAsync(data, 100, data.Length - 100, 100, useAsync);
		await FlushAsync(xts, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.WrittenBytes).IsEqualTo(padded.Length);
			await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<AesCipher>>(padded, unit));
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CachedDataUnitIsVisibleBeforeFlushAndWrittenOnDispose([Matrix] bool useAsync)
	{
		const int unit = 100;
		byte[] data = CreateDeterministicSource(30);
		byte[] padded = new byte[2 * unit];
		data.CopyTo(padded, unit + 10);
		using MemoryStream inner = new();
		DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);
		byte[] actual = new byte[unit];

		await target.WriteAsync(data, 0, data.Length, unit + 10, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.Length).IsZero();
			await Assert.That(xts.Length).IsEqualTo(padded.Length);
			await Assert.That(xts.Seek(0, SeekOrigin.End)).IsEqualTo(padded.Length);
			await Assert.That(await target.ReadAsync(actual, 0, actual.Length, unit, useAsync)).IsEqualTo(unit);
			await AssertBytesEqual(actual, padded.AsSpan(unit).ToArray());
			await Assert.That(inner.Length).IsZero();
		}

		if (useAsync)
		{
			await xts.DisposeAsync();
		}
		else
		{
			xts.Dispose();
		}

		await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<AesCipher>>(padded, unit));
	}

	[Test]
	public async Task SetLengthDiscardsCachedDataUnitPastNewEnd()
	{
		const int unit = 64;
		using MemoryStream inner = new();
		using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		byte[] buffer = new byte[4 * unit];

		xts.Position = 3 * unit + 5;
		xts.Write(CreateDeterministicSource(7));
		xts.SetLength(2 * unit);

		using (Assert.Multiple())
		{
			await Assert.That(xts.Length).IsEqualTo(2 * unit);
			await Assert.That(xts.Position).IsEqualTo(2 * unit);
		}

		xts.SetLength(4 * unit);
		xts.Flush();
		xts.Position = 0;

		using (Assert.Multiple())
		{
			await Assert.That(xts.Read(buffer)).IsEqualTo(buffer.Length);
			await Assert.That(buffer).All(static value => value is 0);
			await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<AesCipher>>(new byte[4 * unit], unit));
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DataUnitNumberOverflowIsRejectedBeforeCaching([Matrix] bool useAsync)
	{
		const int unit = DefaultDataUnitSize;
		byte[] data = CreateDeterministicSource(unit);
		using MemoryStream inner = new();
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, UInt128.MaxValue, true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);
		XtsShadow shadow = new(unit, 2 * unit);
		await WriteAndRecord(target, shadow, data, 0, unit, 0, useAsync);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow, UInt128.MaxValue);

		using (Assert.Multiple())
		{
			await Assert.That(async () => await target.WriteAsync(data, 0, 1, unit, useAsync)).ThrowsExactly<OverflowException>();
			await Assert.That(async () => await target.WriteAsync(data, 0, 2, unit - 1, useAsync)).ThrowsExactly<OverflowException>();
			await Assert.That(() => xts.SetLength(2 * unit)).ThrowsExactly<OverflowException>();
		}

		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow, UInt128.MaxValue);
	}

	[Test]
	[MatrixDataSource]
	public async Task WriteInDataUnitPastLargestOffsetIsRejectedBeforeCaching([Matrix] bool useAsync)
	{
		using MemoryStream inner = new();
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), 4096, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);
		byte[] data = new byte[5];

		// The write itself ends before long.MaxValue, but its data unit does not.
		await Assert.That(async () => await target.WriteAsync(data, 0, data.Length, long.MaxValue - 10, useAsync)).ThrowsExactly<OverflowException>();
		await Assert.That(xts.Length).IsZero();
	}

	[Test]
	[MatrixDataSource]
	public async Task ArrayOverloadsForwardAndValidate([Matrix] bool useAsync)
	{
		const int unit = 100;
		byte[] source = CreateDeterministicSource(260);
		byte[] padded = new byte[300];
		source.AsSpan(10, 230).CopyTo(padded);
		using MemoryStream inner = new();
		using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		byte[] destination = new byte[320];
		PrepareDestination(destination);

		if (useAsync)
		{
			await xts.WriteAsync(source, 10, 230);
		}
		else
		{
			xts.Write(source, 10, 230);
		}

		xts.Position = 0;
		int read = useAsync ? await xts.ReadAsync(destination, 7, 310) : xts.Read(destination, 7, 310);

		using (Assert.Multiple())
		{
			await Assert.That(read).IsEqualTo(padded.Length);
			await AssertOutput(destination, 7, padded);
			await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<AesCipher>>(padded, unit));
			await Assert.That(() => xts.Read(null!, 0, 1)).ThrowsExactly<ArgumentNullException>().WithParameterName("buffer");
			await Assert.That(() => xts.Read(destination, -1, 1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("offset");
			await Assert.That(() => xts.Read(destination, 1, destination.Length)).Throws<ArgumentException>();
			await Assert.That(() => xts.Write(null!, 0, 1)).ThrowsExactly<ArgumentNullException>().WithParameterName("buffer");
			await Assert.That(() => xts.Write(source, 0, -1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("count");
			await Assert.That(() => xts.ReadAsync(null!, 0, 1)).ThrowsExactly<ArgumentNullException>().WithParameterName("buffer");
			await Assert.That(() => xts.WriteAsync(source, source.Length, 1)).Throws<ArgumentException>();
			await Assert.That(xts.Length).IsEqualTo(padded.Length);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CopyToRoundTrips([Matrix] bool useAsync)
	{
		const int unit = DefaultDataUnitSize;
		byte[] plaintext = CreateDeterministicSource(200 * unit + 77);
		byte[] padded = PadToDataUnits(plaintext, unit);
		using MemoryStream source = new(plaintext, false);
		using MemoryStream inner = new();
		using MemoryStream destination = new();
		await using DataUnitStream<XtsMode<SM4Cipher>> xts = DataUnitStream.Create(inner, XtsMode<SM4Cipher>.Create(Key), unit, leaveOpen: true);

		if (useAsync)
		{
			await source.CopyToAsync(xts);
			xts.Position = 0;
			await xts.CopyToAsync(destination);
		}
		else
		{
			source.CopyTo(xts);
			xts.Position = 0;
			xts.CopyTo(destination);
		}

		using (Assert.Multiple())
		{
			await AssertBytesEqual(inner.ToArray(), Encrypt<XtsMode<SM4Cipher>>(padded, unit));
			await AssertBytesEqual(destination.ToArray(), padded);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ShortInnerReadsAreCompleted([Matrix] bool useAsync)
	{
		const int unit = 100;
		XtsShadow shadow = new(unit, 1000);
		shadow.Write(CreateDeterministicSource(700), 0);
		using LimitedReadMemoryStream inner = new(7);
		inner.Write(Encrypt<XtsMode<AesCipher>>(shadow.Span, unit));
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);

		await ReadAndCompare(target, shadow, 0, 700, 0, useAsync);
		await ReadAndCompare(target, shadow, 0, 333, 151, useAsync);
		await WriteAndRecord(target, shadow, CreateDeterministicSource(250), 3, 240, 155, useAsync);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow);
	}

	[Test]
	[MatrixDataSource]
	public async Task BackendLengthNotWholeDataUnitsIsRejected([Matrix] bool useAsync)
	{
		const int unit = 16;
		using MemoryStream partial = new(new byte[3 * unit + 1]);
		using TrackingXtsCipher cipher = TrackingXtsCipher.Create(Key);

		using (Assert.Multiple())
		{
			await Assert.That(() => new DataUnitStream<TrackingXtsCipher>(partial, cipher, unit)).ThrowsExactly<ArgumentException>().WithParameterName("inner");
			await Assert.That(partial.CanRead).IsTrue();
			await Assert.That(cipher.IsDisposed).IsFalse();
		}

		using MemoryStream inner = new();
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);
		byte[] buffer = new byte[2 * unit];
		await target.WriteAsync(CreateDeterministicSource(4 * unit), 0, 4 * unit, 0, useAsync);

		inner.SetLength(3 * unit + 5);

		using (Assert.Multiple())
		{
			await Assert.That(async () => await target.ReadAsync(buffer, 0, 1, 0, useAsync)).ThrowsExactly<InvalidDataException>();
			await Assert.That(async () => await target.WriteAsync(buffer, 0, 1, 0, useAsync)).ThrowsExactly<InvalidDataException>();
			await Assert.That(() => xts.SetLength(unit)).ThrowsExactly<InvalidDataException>();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task PrematureEndInsideDataUnitIsRejected([Matrix] bool useAsync)
	{
		const int unit = 100;
		using LimitedReadMemoryStream inner = new(end: 250);
		inner.Write(new byte[3 * unit]);
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitStreamTarget target = new(xts, inner.ToArray);
		byte[] buffer = new byte[3 * unit];

		using (Assert.Multiple())
		{
			await Assert.That(async () => await target.ReadAsync(buffer, 0, buffer.Length, 0, useAsync)).ThrowsExactly<InvalidDataException>();
			await Assert.That(async () => await target.ReadAsync(buffer, 0, 1, 2 * unit + 60, useAsync)).ThrowsExactly<InvalidDataException>();
			await Assert.That(async () => await target.WriteAsync(buffer, 0, 1, 2 * unit + 60, useAsync)).ThrowsExactly<InvalidDataException>();
		}
	}

	[Test]
	public async Task ConstructorRejectsInvalidArguments()
	{
		using MemoryStream inner = new();
		using NonSeekableMemoryStream nonSeekable = new();
		using XtsMode<AesCipher> cipher = XtsMode<AesCipher>.Create(Key);

		using (Assert.Multiple())
		{
			await Assert.That(() => DataUnitStream.Create(null!, cipher, DefaultDataUnitSize)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => DataUnitStream.Create(nonSeekable, cipher, DefaultDataUnitSize)).ThrowsExactly<ArgumentException>().WithParameterName("inner");
			await Assert.That(() => DataUnitStream.Create<XtsMode<AesCipher>>(inner, null!, DefaultDataUnitSize)).ThrowsExactly<ArgumentNullException>().WithParameterName("cipher");
			await Assert.That(() => DataUnitStream.Create(inner, new ShortTweakCipher(), DefaultDataUnitSize)).ThrowsExactly<ArgumentException>().WithParameterName("cipher");
			await Assert.That(() => DataUnitStream.Create(inner, cipher, 15)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("dataUnitSize");
			await Assert.That(inner.CanRead).IsTrue();
		}
	}

	[Test]
	public async Task CapabilitiesMirrorInnerStream()
	{
		const int unit = 16;
		byte[] ciphertext = Encrypt<XtsMode<AesCipher>>(CreateDeterministicSource(2 * unit), unit);
		using MemoryStream inner = new(ciphertext, false);
		using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit);
		byte[] buffer = new byte[2 * unit];

		using (Assert.Multiple())
		{
			await Assert.That(xts.CanRead).IsTrue();
			await Assert.That(xts.CanWrite).IsFalse();
			await Assert.That(xts.CanSeek).IsTrue();
			await Assert.That(xts.Read(buffer)).IsEqualTo(buffer.Length);
			await AssertBytesEqual(buffer, CreateDeterministicSource(2 * unit));
			await Assert.That(() => xts.Write(buffer)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => xts.Write(buffer.AsSpan(0, 1))).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => xts.WriteAsync(buffer.AsMemory(0, 1)).AsTask()).ThrowsExactly<NotSupportedException>();
		}

		using WriteOnlyMemoryStream writeOnly = new();
		using DataUnitStream<XtsMode<AesCipher>> writer = DataUnitStream.Create(writeOnly, XtsMode<AesCipher>.Create(Key), unit);
		writer.Write(buffer.AsSpan(0, 1));
		writer.Position = 0;

		using (Assert.Multiple())
		{
			await Assert.That(writer.CanRead).IsFalse();
			await Assert.That(() => writer.Read(buffer)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => writer.ReadAsync(buffer).AsTask()).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task AsyncOperationsHonorPreCanceledToken()
	{
		const int unit = 16;
		using MemoryStream inner = new();
		await using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		xts.Write(CreateDeterministicSource(2 * unit));
		xts.Position = 0;
		byte[] backend = inner.ToArray();
		byte[] buffer = new byte[unit];
		using CancellationTokenSource cancellation = new();
		await cancellation.CancelAsync();

		using (Assert.Multiple())
		{
			await Assert.That(() => xts.ReadAsync(buffer, cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(() => xts.WriteAsync(buffer, cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(() => xts.FlushAsync(cancellation.Token)).Throws<OperationCanceledException>();
			await Assert.That(xts.Position).IsZero();
			await AssertBytesEqual(inner.ToArray(), backend);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task FlushForwardsToInnerStream([Matrix] bool useAsync)
	{
		using CountingMemoryStream inner = new();
		using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(inner, XtsMode<AesCipher>.Create(Key), DefaultDataUnitSize, leaveOpen: true);

		await FlushAsync(xts, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.FlushCount).IsEqualTo(useAsync ? 0 : 1);
			await Assert.That(inner.FlushAsyncCount).IsEqualTo(useAsync ? 1 : 0);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposeReleasesCipherAndHonorsLeaveOpen([Matrix] bool leaveOpen, [Matrix] bool useAsync)
	{
		using CountingMemoryStream inner = new();
		TrackingXtsCipher cipher = TrackingXtsCipher.Create(Key);
		DataUnitStream<TrackingXtsCipher> xts = DataUnitStream.Create(inner, cipher, DefaultDataUnitSize, leaveOpen: leaveOpen);
		xts.Write(CreateDeterministicSource(DefaultDataUnitSize));
		byte[] buffer = new byte[DefaultDataUnitSize];

		if (useAsync)
		{
			await xts.DisposeAsync();
			await xts.DisposeAsync();
		}
		else
		{
			xts.Dispose();
		}

		xts.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(cipher.IsDisposed).IsTrue();
			await Assert.That(() => cipher.Encrypt(new byte[16], buffer, buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(inner.CanRead).IsEqualTo(leaveOpen);
			await Assert.That(inner.DisposeCount).IsEqualTo(leaveOpen ? 0 : 1);
			await Assert.That(inner.DisposeAsyncCount).IsEqualTo(!leaveOpen && useAsync ? 1 : 0);
			await Assert.That(xts.CanRead).IsFalse();
			await Assert.That(xts.CanWrite).IsFalse();
			await Assert.That(xts.CanSeek).IsFalse();
			await Assert.That(() => xts.Length).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Position).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Position = 0).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Seek(0, SeekOrigin.Begin)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.SetLength(0)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Read(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Read(buffer, 0, 1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(xts.ReadByte).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Write(buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Write(buffer, 0, 1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.WriteByte(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.ReadAsync(buffer).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.WriteAsync(buffer).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(xts.Flush).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(xts.FlushAsync).ThrowsExactly<ObjectDisposedException>();
		}
	}

	private static async ValueTask FlushAsync(Stream stream, bool useAsync)
	{
		if (useAsync)
		{
			await stream.FlushAsync();
		}
		else
		{
			stream.Flush();
		}
	}

	private sealed class DataUnitStreamTarget(Stream xts, Func<byte[]> readBackend) : IDataUnitTarget
	{
		public long GetLength()
		{
			return xts.Length;
		}

		public void SetLength(long length)
		{
			xts.SetLength(length);
		}

		public async ValueTask<int> ReadAsync(byte[] buffer, int index, int count, long offset, bool useAsync)
		{
			xts.Position = offset;
			int read;

			if (useAsync)
			{
				read = await xts.ReadAsync(buffer.AsMemory(index, count));
			}
			else
			{
				read = xts.Read(buffer.AsSpan(index, count));
			}

			await Assert.That(xts.Position).IsEqualTo(offset + read);
			return read;
		}

		public async ValueTask WriteAsync(byte[] buffer, int index, int count, long offset, bool useAsync)
		{
			xts.Position = offset;

			if (useAsync)
			{
				await xts.WriteAsync(buffer.AsMemory(index, count));
			}
			else
			{
				xts.Write(buffer.AsSpan(index, count));
			}

			await Assert.That(xts.Position).IsEqualTo(offset + count);
		}

		public byte[] ReadBackend()
		{
			xts.Flush();
			return readBackend();
		}
	}

	private sealed class NonSeekableMemoryStream : MemoryStream
	{
		public override bool CanSeek => false;
	}

	/// <summary>Counts calls; derived memory streams route every read and write through the array overloads.</summary>
	private sealed class CountingMemoryStream : MemoryStream
	{
		public int ReadCount { get; private set; }

		public int WriteCount { get; private set; }

		public long WrittenBytes { get; private set; }

		public int FlushCount { get; private set; }

		public int FlushAsyncCount { get; private set; }

		public int DisposeCount { get; private set; }

		public int DisposeAsyncCount { get; private set; }

		public override int Read(byte[] buffer, int offset, int count)
		{
			++ReadCount;
			return base.Read(buffer, offset, count);
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			++WriteCount;
			WrittenBytes += count;
			base.Write(buffer, offset, count);
		}

		public override void Flush()
		{
			++FlushCount;
			base.Flush();
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			// MemoryStream.FlushAsync would call Flush and blur the two counters.
			++FlushAsyncCount;
			return cancellationToken.IsCancellationRequested ? Task.FromCanceled(cancellationToken) : Task.CompletedTask;
		}

		public override ValueTask DisposeAsync()
		{
			++DisposeAsyncCount;
			return base.DisposeAsync();
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				++DisposeCount;
			}

			base.Dispose(disposing);
		}
	}
}
