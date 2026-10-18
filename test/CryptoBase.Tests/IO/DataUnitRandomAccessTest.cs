using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;
using CryptoBase.IO.DataUnits;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.IO.XtsTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class DataUnitRandomAccessTest
{
	private const int DefaultDataUnitSize = 512;

	[Test]
	[GenerateGenericTest(typeof(XtsMode<AesCipher>))]
	[GenerateGenericTest(typeof(XtsMode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task WholeWriteMatchesOracleAndReadsBack<TCipher>([Matrix(16, 100, 512, 4096)] int dataUnitSize, [Matrix] bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		byte[] plaintext = CreateDeterministicSource(RoundUp(70_000, dataUnitSize));
		byte[] original = plaintext.ToArray();
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<TCipher> xts = DataUnitRandomAccess.Create(handle, TCipher.Create(Key), dataUnitSize, leaveOpen: true);
		DataUnitRandomAccessTarget<TCipher> target = new(xts, handle);
		XtsShadow shadow = new(dataUnitSize, plaintext.Length);

		await WriteAndRecord(target, shadow, plaintext, 0, plaintext.Length, 0, useAsync);
		xts.Flush();

		using (Assert.Multiple())
		{
			await Assert.That(xts.DataUnitSize).IsEqualTo(dataUnitSize);
			await AssertBytesEqual(plaintext, original);
			await AssertBytesEqual(ReadAll(handle), Encrypt<TCipher>(plaintext, dataUnitSize));
		}

		int length = plaintext.Length;
		await ReadAndCompare(target, shadow, 0, length, 0, useAsync);
		await ReadAndCompare(target, shadow, 3, length - 2, 1, useAsync);
		await ReadAndCompare(target, shadow, 0, 2, dataUnitSize - 1, useAsync);
		await ReadAndCompare(target, shadow, 1, 2 * dataUnitSize, dataUnitSize + 3, useAsync);
		await ReadAndCompare(target, shadow, 0, dataUnitSize - 1, 2 * dataUnitSize, useAsync);
		await ReadAndCompare(target, shadow, 0, 100, length - 5, useAsync);
	}

	[Test]
	[GenerateGenericTest(typeof(XtsMode<AesCipher>))]
	[GenerateGenericTest(typeof(XtsMode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task WritesAtArbitraryOffsetsMatchShadow<TCipher>([Matrix(16, 100, 512, 4096)] int dataUnitSize, [Matrix] bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		int unit = dataUnitSize;
		int chunk = DataUnitTransform<TCipher>.GetChunkSize(dataUnitSize);
		int length = RoundUp(2 * chunk + 4 * unit, unit);
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<TCipher> xts = DataUnitRandomAccess.Create(handle, TCipher.Create(Key), dataUnitSize, leaveOpen: true);
		DataUnitRandomAccessTarget<TCipher> target = new(xts, handle);
		XtsShadow shadow = new(dataUnitSize, length + unit);
		byte[] initial = CreateDeterministicSource(length);
		await WriteAndRecord(target, shadow, initial, 0, length, 0, useAsync);
		Random random = new(unit);

		(int Offset, int Count)[] cases =
		[
			(unit, 2 * unit), // Aligned whole units.
			(unit + 3, unit - 3), // Partial head unit only.
			(2 * unit, 5), // Partial tail unit only.
			(unit + 5, 3 * unit), // Head, middle and tail.
			(3 * unit + 2, unit / 2), // Inside one unit.
			(unit - 1, chunk + 2 * unit + 2), // Middle spans more than one chunk.
			(chunk - 7, 14), // Partial head and tail units in one window.
			(length - unit + 1, unit - 2) // Inside the last unit.
		];

		foreach ((int offset, int count) in cases)
		{
			byte[] source = new byte[count + 3];
			random.NextBytes(source);
			byte[] original = source.ToArray();

			await WriteAndRecord(target, shadow, source, 3, count, offset, useAsync);

			await AssertBytesEqual(source, original);
			await ReadAndCompare(target, shadow, 1, count, offset, useAsync);
			await AssertMatchesShadow<TCipher>(target, shadow);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(XtsMode<AesCipher>))]
	[GenerateGenericTest(typeof(XtsMode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task FuzzMatchesShadow<TCipher>([Matrix(16, 100, 512, 4096)] int dataUnitSize, [Matrix] bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<TCipher> xts = DataUnitRandomAccess.Create(handle, TCipher.Create(Key), dataUnitSize, leaveOpen: true);

		await RunFuzz<TCipher>(new DataUnitRandomAccessTarget<TCipher>(xts, handle), new XtsShadow(dataUnitSize, 512 * 1024), 0x5EED + dataUnitSize, 300, useAsync);
	}

	[Test]
	[MatrixDataSource]
	public async Task ExtensionWriteZeroFillsPaddingAndHole([Matrix] bool useAsync)
	{
		const int unit = DefaultDataUnitSize;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitRandomAccessTarget<XtsMode<AesCipher>> target = new(xts, handle);
		XtsShadow shadow = new(unit, 8 * unit);
		await WriteAndRecord(target, shadow, CreateDeterministicSource(2 * unit), 0, 2 * unit, 0, useAsync);

		byte[] data = CreateDeterministicSource(7);
		await WriteAndRecord(target, shadow, data, 0, data.Length, 5 * unit + 100, useAsync);

		byte[] expected = new byte[4 * unit];
		data.CopyTo(expected, 3 * unit + 100);
		byte[] actual = new byte[4 * unit];

		using (Assert.Multiple())
		{
			await Assert.That(xts.GetLength()).IsEqualTo(6 * unit);
			await Assert.That(await target.ReadAsync(actual, 0, actual.Length, 2 * unit, useAsync)).IsEqualTo(actual.Length);
			await AssertBytesEqual(actual, expected);
			await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow);
		}
	}

	[Test]
	public async Task SetLengthGrowsWithZerosAndShrinks()
	{
		const int unit = DefaultDataUnitSize;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle();
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitRandomAccessTarget<XtsMode<AesCipher>> target = new(xts, handle);
		XtsShadow shadow = new(unit, 200 * unit);
		await WriteAndRecord(target, shadow, CreateDeterministicSource(3 * unit), 0, 3 * unit, 0, false);

		xts.SetLength(150 * unit);
		shadow.SetLength(150 * unit);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow);
		await Assert.That(shadow.Read(3 * unit, 147 * unit)).All(static value => value is 0);

		xts.SetLength(2 * unit);
		shadow.SetLength(2 * unit);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow);

		// Growing again must not resurrect the truncated plaintext.
		xts.SetLength(4 * unit);
		shadow.SetLength(4 * unit);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow);
		await Assert.That(shadow.Read(2 * unit, 2 * unit)).All(static value => value is 0);

		xts.SetLength(4 * unit);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow);

		using (Assert.Multiple())
		{
			await Assert.That(() => xts.SetLength(-1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("length");
			await Assert.That(() => xts.SetLength(unit + 1)).ThrowsExactly<ArgumentException>().WithParameterName("length");
			await Assert.That(xts.GetLength()).IsEqualTo(4 * unit);
		}
	}

	[Test]
	public async Task ConstructorRejectsPartialDataUnitLength()
	{
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle();
		RandomAccess.Write(handle, CreateDeterministicSource(3 * DefaultDataUnitSize + 1), 0);
		using TrackingXtsCipher cipher = TrackingXtsCipher.Create(Key);

		using (Assert.Multiple())
		{
			await Assert.That(() => new DataUnitRandomAccess<TrackingXtsCipher>(handle, cipher, DefaultDataUnitSize)).ThrowsExactly<ArgumentException>().WithParameterName("handle");
			await Assert.That(handle.IsClosed).IsFalse();
			await Assert.That(cipher.IsDisposed).IsFalse();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task TruncatedBackendIsRejectedAtRuntime([Matrix] bool useAsync)
	{
		const int unit = DefaultDataUnitSize;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitRandomAccessTarget<XtsMode<AesCipher>> target = new(xts, handle);
		byte[] buffer = new byte[2 * unit];
		await target.WriteAsync(CreateDeterministicSource(4 * unit), 0, 4 * unit, 0, useAsync);

		RandomAccess.SetLength(handle, 3 * unit + 5);

		using (Assert.Multiple())
		{
			await Assert.That(async () => await target.ReadAsync(buffer, 0, 1, 0, useAsync)).ThrowsExactly<InvalidDataException>();
			await Assert.That(async () => await target.WriteAsync(buffer, 0, 1, 0, useAsync)).ThrowsExactly<InvalidDataException>();
			await Assert.That(() => xts.SetLength(unit)).ThrowsExactly<InvalidDataException>();
			await Assert.That(xts.GetLength()).IsEqualTo(3 * unit + 5);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(XtsMode<AesCipher>))]
	[GenerateGenericTest(typeof(XtsMode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task FirstDataUnitNumberSelectsTweaks<TCipher>([Matrix] bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		const int unit = 100;
		// The unit numbers carry from the low into the high 64-bit half.
		UInt128 first = new(0x0123_4567_89AB_CDEF, ulong.MaxValue - 2);
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<TCipher> xts = DataUnitRandomAccess.Create(handle, TCipher.Create(Key), unit, first, true);
		DataUnitRandomAccessTarget<TCipher> target = new(xts, handle);
		XtsShadow shadow = new(unit, 8 * unit);

		await WriteAndRecord(target, shadow, CreateDeterministicSource(6 * unit + 7), 0, 6 * unit + 7, 0, useAsync);

		await AssertMatchesShadow<TCipher>(target, shadow, first);
		await ReadAndCompare(target, shadow, 0, 3 * unit, unit + 50, useAsync);
	}

	[Test]
	[MatrixDataSource]
	public async Task DataUnitNumberOverflowIsRejectedBeforeWriting([Matrix] bool useAsync)
	{
		const int unit = DefaultDataUnitSize;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, UInt128.MaxValue, true);
		DataUnitRandomAccessTarget<XtsMode<AesCipher>> target = new(xts, handle);
		XtsShadow shadow = new(unit, 2 * unit);
		byte[] data = CreateDeterministicSource(unit);

		await WriteAndRecord(target, shadow, data, 0, unit, 0, useAsync);
		await AssertMatchesShadow<XtsMode<AesCipher>>(target, shadow, UInt128.MaxValue);
		byte[] backend = ReadAll(handle);

		using (Assert.Multiple())
		{
			await Assert.That(async () => await target.WriteAsync(data, 0, 1, unit, useAsync)).ThrowsExactly<OverflowException>();
			await Assert.That(async () => await target.WriteAsync(data, 0, 2, unit - 1, useAsync)).ThrowsExactly<OverflowException>();
			await Assert.That(() => xts.SetLength(2 * unit)).ThrowsExactly<OverflowException>();
			await AssertBytesEqual(ReadAll(handle), backend);
		}
	}

	[Test]
	public async Task ConstructorRejectsInvalidArguments()
	{
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle();
		using XtsMode<AesCipher> cipher = XtsMode<AesCipher>.Create(Key);

		using (Assert.Multiple())
		{
			await Assert.That(() => DataUnitRandomAccess.Create(null!, cipher, DefaultDataUnitSize)).ThrowsExactly<ArgumentNullException>().WithParameterName("handle");
			await Assert.That(() => DataUnitRandomAccess.Create<XtsMode<AesCipher>>(handle, null!, DefaultDataUnitSize)).ThrowsExactly<ArgumentNullException>().WithParameterName("cipher");
			await Assert.That(() => DataUnitRandomAccess.Create(handle, new ShortTweakCipher(), DefaultDataUnitSize)).ThrowsExactly<ArgumentException>().WithParameterName("cipher");

			foreach (int dataUnitSize in new[] { 15, 0, -1 })
			{
				await Assert.That(() => DataUnitRandomAccess.Create(handle, cipher, dataUnitSize)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("dataUnitSize");
			}

			await Assert.That(handle.IsClosed).IsFalse();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ReadAtOrPastEndReturnsZero([Matrix] bool useAsync)
	{
		const int unit = DefaultDataUnitSize;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		DataUnitRandomAccessTarget<XtsMode<AesCipher>> target = new(xts, handle);
		XtsShadow shadow = new(unit, 2 * unit);
		await WriteAndRecord(target, shadow, CreateDeterministicSource(2 * unit), 0, 2 * unit, 0, useAsync);

		await ReadAndCompare(target, shadow, 0, 10, 2 * unit, useAsync);
		await ReadAndCompare(target, shadow, 0, 10, 10 * unit + 3, useAsync);
		await ReadAndCompare(target, shadow, 0, 0, 0, useAsync);
		await Assert.That(xts.GetLength()).IsEqualTo(2 * unit);
	}

	[Test]
	[MatrixDataSource]
	public async Task EmptyWriteDoesNotExtend([Matrix] bool useAsync)
	{
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(useAsync);
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), DefaultDataUnitSize, leaveOpen: true);
		DataUnitRandomAccessTarget<XtsMode<AesCipher>> target = new(xts, handle);

		await target.WriteAsync([], 0, 0, 10 * DefaultDataUnitSize + 1, useAsync);

		await Assert.That(xts.GetLength()).IsZero();
	}

	[Test]
	public async Task NegativeOffsetsAreRejected()
	{
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle();
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), DefaultDataUnitSize, leaveOpen: true);
		byte[] buffer = new byte[16];

		using (Assert.Multiple())
		{
			await Assert.That(() => xts.Read(buffer, -1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("offset");
			await Assert.That(() => xts.Write(buffer, -1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("offset");
			await Assert.That(() => xts.ReadAsync(buffer, -1).AsTask()).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("offset");
			await Assert.That(() => xts.WriteAsync(buffer, -1).AsTask()).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("offset");
			await Assert.That(xts.GetLength()).IsZero();
		}
	}

	[Test]
	public async Task AsyncOperationsHonorPreCanceledToken()
	{
		const int unit = DefaultDataUnitSize;
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(true);
		using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
		await xts.WriteAsync(CreateDeterministicSource(unit), 0);
		byte[] backend = ReadAll(handle);
		byte[] buffer = new byte[unit];
		PrepareDestination(buffer);
		using CancellationTokenSource cancellation = new();
		await cancellation.CancelAsync();

		using (Assert.Multiple())
		{
			await Assert.That(() => xts.ReadAsync(buffer, 0, cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(() => xts.WriteAsync(CreateDeterministicSource(2 * unit), unit, cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(buffer).All(static value => value is DestinationSentinel);
			await AssertBytesEqual(ReadAll(handle), backend);
		}
	}

	[Test]
	public async Task InstancesSharingHandleReadInParallel()
	{
		const int unit = 4096;
		byte[] plaintext = CreateDeterministicSource(64 * unit);
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle(true);

		using (DataUnitRandomAccess<XtsMode<AesCipher>> writer = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true))
		{
			await writer.WriteAsync(plaintext, 0);
		}

		Task<byte[]>[] readers = new Task<byte[]>[4];

		for (int i = 0; i < readers.Length; ++i)
		{
			int start = i * plaintext.Length / readers.Length;
			readers[i] = Task.Run(async () =>
			{
				using DataUnitRandomAccess<XtsMode<AesCipher>> reader = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(Key), unit, leaveOpen: true);
				byte[] buffer = new byte[plaintext.Length / readers.Length];
				await Assert.That(await reader.ReadAsync(buffer, start)).IsEqualTo(buffer.Length);
				return buffer;
			});
		}

		byte[][] parts = await Task.WhenAll(readers);

		await AssertBytesEqual(parts.SelectMany(static part => part).ToArray(), plaintext);
		await Assert.That(handle.IsClosed).IsFalse();
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposeReleasesCipherAndHonorsLeaveOpen([Matrix] bool leaveOpen)
	{
		using TempFile file = new();
		using SafeFileHandle handle = file.OpenHandle();
		TrackingXtsCipher cipher = TrackingXtsCipher.Create(Key);
		DataUnitRandomAccess<TrackingXtsCipher> xts = DataUnitRandomAccess.Create(handle, cipher, DefaultDataUnitSize, leaveOpen: leaveOpen);
		xts.Write(CreateDeterministicSource(DefaultDataUnitSize), 0);
		byte[] buffer = new byte[DefaultDataUnitSize];

		xts.Dispose();
		xts.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(cipher.IsDisposed).IsTrue();
			await Assert.That(() => cipher.Encrypt(new byte[16], buffer, buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(handle.IsClosed).IsEqualTo(!leaveOpen);
			await Assert.That(xts.GetLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.SetLength(0)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Read(buffer, 0)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.Write(buffer, 0)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.ReadAsync(buffer, 0).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xts.WriteAsync(buffer, 0).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(xts.Flush).ThrowsExactly<ObjectDisposedException>();
		}
	}
}
