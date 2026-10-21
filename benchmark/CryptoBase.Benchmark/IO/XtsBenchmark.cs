using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.IO;

internal static class XtsBenchmarkData
{
	/// <summary>The plaintext size moved by every benchmark invocation: 1 MiB.</summary>
	public const int TotalLength = 1024 * 1024;

	/// <summary>Creates AES-256-XTS from a fixed 64-byte key (32-byte data key followed by 32-byte tweak key).</summary>
	public static XtsMode<AesCipher> CreateCipher()
	{
		Span<byte> key = stackalloc byte[64];

		for (int i = 0; i < key.Length; ++i)
		{
			key[i] = (byte)i;
		}

		return XtsMode<AesCipher>.Create(key);
	}
}

/// <summary>
/// Sequential <see cref="DataUnitStream{TCipher}" /> throughput over a <see cref="MemoryStream" /> with AES-256-XTS.
/// </summary>
/// <remarks>
/// Every invocation moves exactly <see cref="XtsBenchmarkData.TotalLength" /> (1 MiB) of plaintext in calls of
/// <see cref="ChunkSize" /> bytes (the last call may be shorter), so MiB/s = 1 / Mean in seconds. <see cref="Write" />
/// truncates the stream first and ends with <see cref="Stream.Flush()" />, which writes the last cached data unit.
/// Chunks smaller than a data unit go through the stream's one-unit plaintext cache, so each data unit is still
/// encrypted or decrypted once.
/// </remarks>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class XtsStreamBenchmark
{
	[Params(512, 4096)]
	public int DataUnitSize { get; set; }

	[Params(100, 4096, 64 * 1024)]
	public int ChunkSize { get; set; }

	private byte[] _plaintext = [];
	private byte[] _buffer = [];
	private DataUnitStream<XtsMode<AesCipher>> _writeStream = null!;
	private DataUnitStream<XtsMode<AesCipher>> _readStream = null!;

	[GlobalSetup]
	public void Setup()
	{
		_plaintext = RandomNumberGenerator.GetBytes(XtsBenchmarkData.TotalLength);
		_buffer = new byte[ChunkSize];

		_writeStream = DataUnitStream.Create(new MemoryStream(XtsBenchmarkData.TotalLength), XtsBenchmarkData.CreateCipher(), DataUnitSize);

		_readStream = DataUnitStream.Create(new MemoryStream(XtsBenchmarkData.TotalLength), XtsBenchmarkData.CreateCipher(), DataUnitSize);
		_readStream.Write(_plaintext);
		_readStream.Flush();
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_writeStream.Dispose();
		_readStream.Dispose();
	}

	[Benchmark]
	[BenchmarkCategory("Write")]
	public long Write()
	{
		DataUnitStream<XtsMode<AesCipher>> stream = _writeStream;
		stream.SetLength(0);
		ReadOnlySpan<byte> source = _plaintext;

		for (int offset = 0; offset < source.Length; offset += ChunkSize)
		{
			stream.Write(source.Slice(offset, Math.Min(ChunkSize, source.Length - offset)));
		}

		stream.Flush();
		return stream.Position;
	}

	[Benchmark]
	[BenchmarkCategory("Read")]
	public long Read()
	{
		DataUnitStream<XtsMode<AesCipher>> stream = _readStream;
		stream.Position = 0;
		Span<byte> buffer = _buffer;
		long total = 0;

		while (total < XtsBenchmarkData.TotalLength)
		{
			int read = stream.Read(buffer.Slice(0, (int)Math.Min(buffer.Length, XtsBenchmarkData.TotalLength - total)));

			if (read is 0)
			{
				throw new EndOfStreamException();
			}

			total += read;
		}

		return total;
	}
}

/// <summary>
/// Positional <see cref="DataUnitRandomAccess{TCipher}" /> throughput over a temporary file with AES-256-XTS.
/// </summary>
/// <remarks>
/// Every invocation moves exactly <see cref="XtsBenchmarkData.TotalLength" /> (1 MiB) of plaintext from offset zero in
/// aligned 64 KiB calls, so MiB/s = 1 / Mean in seconds. The file is opened once with <see cref="FileOptions.None" /> and
/// pre-filled to 1 MiB, so writes overwrite whole data units and never read. <see cref="Write" /> does not call
/// <see cref="DataUnitRandomAccess{TCipher}.Flush" />, which issues <see cref="RandomAccess.FlushToDisk" /> and would measure
/// the disk instead of the XTS path.
/// </remarks>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class XtsRandomAccessBenchmark
{
	private const int ChunkSize = 64 * 1024;

	[Params(512, 4096)]
	public int DataUnitSize { get; set; }

	private string _path = string.Empty;
	private SafeFileHandle _handle = null!;
	private DataUnitRandomAccess<XtsMode<AesCipher>> _xts = null!;
	private byte[] _plaintext = [];
	private byte[] _buffer = [];

	[GlobalSetup]
	public void Setup()
	{
		_path = Path.Combine(Path.GetTempPath(), $"CryptoBase.Benchmark.Xts.{Guid.NewGuid():N}.bin");
		_handle = File.OpenHandle(_path, FileMode.CreateNew, FileAccess.ReadWrite);
		_xts = DataUnitRandomAccess.Create(_handle, XtsBenchmarkData.CreateCipher(), DataUnitSize, leaveOpen: true);
		_plaintext = RandomNumberGenerator.GetBytes(XtsBenchmarkData.TotalLength);
		_buffer = new byte[XtsBenchmarkData.TotalLength];
		_xts.Write(_plaintext, 0);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_xts.Dispose();
		_handle.Dispose();
		File.Delete(_path);
	}

	[Benchmark]
	[BenchmarkCategory("Write")]
	public void Write()
	{
		ReadOnlySpan<byte> source = _plaintext;

		for (int offset = 0; offset < source.Length; offset += ChunkSize)
		{
			_xts.Write(source.Slice(offset, ChunkSize), offset);
		}
	}

	[Benchmark]
	[BenchmarkCategory("Read")]
	public long Read()
	{
		Span<byte> buffer = _buffer;
		long total = 0;

		for (int offset = 0; offset < buffer.Length; offset += ChunkSize)
		{
			total += _xts.Read(buffer.Slice(offset, ChunkSize), offset);
		}

		return total;
	}
}
