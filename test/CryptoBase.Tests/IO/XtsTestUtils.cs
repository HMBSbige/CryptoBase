using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;
using CryptoBase.IO.DataUnits;
using Microsoft.Win32.SafeHandles;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

internal static class XtsTestUtils
{
	public static readonly byte[] Key = CreateDeterministicSource(32);

	public static int RoundUp(int value, int dataUnitSize)
	{
		return (value + dataUnitSize - 1) / dataUnitSize * dataUnitSize;
	}

	/// <summary>Copies <paramref name="data" /> into zeros that fill its last data unit.</summary>
	public static byte[] PadToDataUnits(byte[] data, int dataUnitSize)
	{
		byte[] padded = new byte[RoundUp(data.Length, dataUnitSize)];
		data.CopyTo(padded, 0);
		return padded;
	}

	/// <summary>Encrypts whole data units with the span API, independently of CryptoBase.IO.</summary>
	public static byte[] Encrypt<TCipher>(ReadOnlySpan<byte> plaintext, int dataUnitSize, UInt128 firstDataUnitNumber = default) where TCipher : class, IDataUnitCipher<TCipher>
	{
		if (plaintext.Length % dataUnitSize is not 0)
		{
			throw new ArgumentException("The plaintext must hold whole data units.", nameof(plaintext));
		}

		using TCipher cipher = TCipher.Create(Key);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tweak = new byte[16];

		for (int i = 0; i < plaintext.Length; i += dataUnitSize)
		{
			XtsMode.GetTweak(tweak, firstDataUnitNumber + (ulong)(i / dataUnitSize));
			cipher.Encrypt(tweak, plaintext.Slice(i, dataUnitSize), ciphertext.AsSpan(i, dataUnitSize));
		}

		return ciphertext;
	}

	public static async Task AssertBytesEqual(byte[] actual, byte[] expected)
	{
		int matching = actual.AsSpan().CommonPrefixLength(expected);

		using (Assert.Multiple())
		{
			await Assert.That(actual.Length).IsEqualTo(expected.Length);
			await Assert.That(matching).IsEqualTo(Math.Min(actual.Length, expected.Length));
		}
	}

	/// <summary>Verifies that the target decrypts to the shadow and that the backend matches the oracle ciphertext.</summary>
	public static async Task AssertMatchesShadow<TCipher>(IDataUnitTarget target, XtsShadow shadow, UInt128 firstDataUnitNumber = default) where TCipher : class, IDataUnitCipher<TCipher>
	{
		await Assert.That(target.GetLength()).IsEqualTo(shadow.Length);
		byte[] plaintext = new byte[shadow.Length];
		int read = await target.ReadAsync(plaintext, 0, plaintext.Length, 0, false);
		await Assert.That(read).IsEqualTo(shadow.Length);
		await AssertBytesEqual(plaintext, shadow.ToArray());
		await AssertBytesEqual(target.ReadBackend(), Encrypt<TCipher>(shadow.Span, shadow.DataUnitSize, firstDataUnitNumber));
	}

	/// <summary>Applies the same transfer to the target and the shadow and checks the read results.</summary>
	public static async Task WriteAndRecord(IDataUnitTarget target, XtsShadow shadow, byte[] source, int index, int count, long offset, bool useAsync)
	{
		await target.WriteAsync(source, index, count, offset, useAsync);
		shadow.Write(source.AsSpan(index, count), (int)offset);
	}

	public static async Task ReadAndCompare(IDataUnitTarget target, XtsShadow shadow, int index, int count, long offset, bool useAsync)
	{
		byte[] buffer = CreateGuardedBuffer(index, count, 9);

		int read = await target.ReadAsync(buffer, index, count, offset, useAsync);

		byte[] expected = shadow.Read((int)offset, count);

		using (Assert.Multiple())
		{
			await Assert.That(read).IsEqualTo(expected.Length);
			await AssertBytesEqual(buffer.AsSpan(index, read).ToArray(), expected);
			await Assert.That(buffer.AsMemory(0, index)).All(static value => value is DestinationSentinel);
			await Assert.That(buffer.AsMemory(index + read)).All(static value => value is DestinationSentinel);
		}
	}

	/// <summary>Runs a deterministic sequence of reads, writes and length changes against the target and the shadow.</summary>
	public static async Task RunFuzz<TCipher>(IDataUnitTarget target, XtsShadow shadow, int seed, int operations, bool useAsync) where TCipher : class, IDataUnitCipher<TCipher>
	{
		Random random = new(seed);
		int dataUnitSize = shadow.DataUnitSize;
		int chunk = DataUnitTransform<TCipher>.GetChunkSize(dataUnitSize);
		int maxLength = shadow.Capacity - dataUnitSize;
		byte[] source = new byte[maxLength + 64];

		for (int operation = 0; operation < operations; ++operation)
		{
			int kind = random.Next(20);
			int count = NextCount(random, dataUnitSize, chunk);
			int offset = random.Next(0, Math.Min(shadow.Length + 3 * dataUnitSize, maxLength) + 1);
			count = Math.Min(count, maxLength - offset);

			switch (kind)
			{
				case < 9:
				{
					int index = random.Next(64);
					random.NextBytes(source.AsSpan(index, count));
					await WriteAndRecord(target, shadow, source, index, count, offset, useAsync);
					break;
				}
				case < 19:
				{
					await ReadAndCompare(target, shadow, random.Next(8), count, offset, useAsync);
					break;
				}
				default:
				{
					int length = random.Next(0, Math.Min(shadow.Length + 4 * dataUnitSize, maxLength) / dataUnitSize + 1) * dataUnitSize;
					target.SetLength(length);
					shadow.SetLength(length);
					break;
				}
			}

			if (operation % 50 is 49)
			{
				await AssertMatchesShadow<TCipher>(target, shadow);
			}
		}

		await AssertMatchesShadow<TCipher>(target, shadow);
	}

	private static int NextCount(Random random, int dataUnitSize, int chunk)
	{
		return random.Next(10) switch
		{
			< 5 => random.Next(0, 2 * dataUnitSize + 4),
			< 9 => random.Next(0, 6 * dataUnitSize + 1),
			_ => random.Next(chunk - dataUnitSize, 2 * chunk + 3 * dataUnitSize)
		};
	}

	public static byte[] ReadAll(SafeFileHandle handle)
	{
		byte[] buffer = new byte[RandomAccess.GetLength(handle)];
		int offset = 0;

		while (offset < buffer.Length)
		{
			int read = RandomAccess.Read(handle, buffer.AsSpan(offset), offset);

			if (read is 0)
			{
				throw new EndOfStreamException();
			}

			offset += read;
		}

		return buffer;
	}
}

/// <summary>Tracks the expected plaintext of an XTS backend.</summary>
internal sealed class XtsShadow(int dataUnitSize, int capacity)
{
	private readonly byte[] _data = new byte[capacity];

	public int DataUnitSize { get; } = dataUnitSize;

	public int Capacity => _data.Length;

	public int Length { get; private set; }

	public ReadOnlySpan<byte> Span => _data.AsSpan(0, Length);

	public byte[] ToArray()
	{
		return Span.ToArray();
	}

	public void Write(ReadOnlySpan<byte> source, int offset)
	{
		if (source.IsEmpty)
		{
			return;
		}

		source.CopyTo(_data.AsSpan(offset));
		Length = Math.Max(Length, XtsTestUtils.RoundUp(offset + source.Length, DataUnitSize));
	}

	public byte[] Read(int offset, int count)
	{
		return offset >= Length ? [] : _data.AsSpan(offset, Math.Min(count, Length - offset)).ToArray();
	}

	public void SetLength(int length)
	{
		if (length < Length)
		{
			_data.AsSpan(length, Length - length).Clear();
		}

		Length = length;
	}
}

/// <summary>Abstracts the data-unit facades for shared scenarios.</summary>
internal interface IDataUnitTarget
{
	long GetLength();

	void SetLength(long length);

	ValueTask<int> ReadAsync(byte[] buffer, int index, int count, long offset, bool useAsync);

	ValueTask WriteAsync(byte[] buffer, int index, int count, long offset, bool useAsync);

	byte[] ReadBackend();
}

internal sealed class DataUnitRandomAccessTarget<TCipher>(DataUnitRandomAccess<TCipher> xts, SafeFileHandle handle) : IDataUnitTarget where TCipher : class, IDataUnitCipher<TCipher>
{
	public long GetLength()
	{
		return xts.GetLength();
	}

	public void SetLength(long length)
	{
		xts.SetLength(length);
	}

	public ValueTask<int> ReadAsync(byte[] buffer, int index, int count, long offset, bool useAsync)
	{
		return useAsync ? xts.ReadAsync(buffer.AsMemory(index, count), offset) : ValueTask.FromResult(xts.Read(buffer.AsSpan(index, count), offset));
	}

	public ValueTask WriteAsync(byte[] buffer, int index, int count, long offset, bool useAsync)
	{
		if (useAsync)
		{
			return xts.WriteAsync(buffer.AsMemory(index, count), offset);
		}

		xts.Write(buffer.AsSpan(index, count), offset);
		return ValueTask.CompletedTask;
	}

	public byte[] ReadBackend()
	{
		return XtsTestUtils.ReadAll(handle);
	}
}

/// <summary>A temporary file deleted on disposal.</summary>
internal sealed class TempFile : IDisposable
{
	public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"CryptoBase.Tests.Xts.{Guid.NewGuid():N}.bin");

	public SafeFileHandle OpenHandle(bool useAsync = false)
	{
		return File.OpenHandle(Path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite, useAsync ? FileOptions.Asynchronous : FileOptions.None);
	}

	public void Dispose()
	{
		File.Delete(Path);
	}
}

/// <summary>Wraps XTS-AES and reports disposal by throwing <see cref="ObjectDisposedException" />.</summary>
internal sealed class TrackingXtsCipher : IDataUnitCipher<TrackingXtsCipher>
{
	private readonly XtsMode<AesCipher> _inner;

	private TrackingXtsCipher(XtsMode<AesCipher> inner)
	{
		_inner = inner;
	}

	public bool IsDisposed { get; private set; }

	public static int TweakSize => 16;

	public static TrackingXtsCipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new TrackingXtsCipher(XtsMode<AesCipher>.Create(key));
	}

	public void Dispose()
	{
		IsDisposed = true;
		_inner.Dispose();
	}

	public void Encrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(IsDisposed, this);
		_inner.Encrypt(tweak, source, destination);
	}

	public void Decrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(IsDisposed, this);
		_inner.Decrypt(tweak, source, destination);
	}
}

/// <summary>A data-unit cipher whose tweak is too short for the data-unit facades.</summary>
internal sealed class ShortTweakCipher : IDataUnitCipher<ShortTweakCipher>
{
	public static int TweakSize => 8;

	public static ShortTweakCipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new ShortTweakCipher();
	}

	public void Dispose()
	{
	}

	public void Encrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		throw new NotSupportedException();
	}

	public void Decrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		throw new NotSupportedException();
	}
}
