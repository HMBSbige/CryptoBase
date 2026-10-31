using CryptoBase.IO.Storage;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.IO.DataUnits;

/// <summary>
/// Maps byte ranges onto encrypted data units stored in positional storage.
/// </summary>
/// <remarks>
/// <para>
/// The backend holds whole data units only. The data unit at byte offset <c>n * dataUnitSize</c> is transformed with the little-endian 128-bit tweak <c>firstDataUnitNumber + n</c>.
/// </para>
/// <para>
/// Aligned reads land directly in the caller's buffer and are decrypted in place; partial data units go through a pooled scratch unit. Writes assemble whole data units in a pooled window: encrypted zeros for any gap after the old end, the caller's data, and the existing plaintext around partially written units. Each window is encrypted in place and written with one backend call, so the caller's buffer is never modified. Read scratch units are cleared before they are returned; a written window holds only ciphertext, so write windows are cleared only when a write fails.
/// Instances are not thread-safe.
/// </para>
/// </remarks>
internal sealed class DataUnitTransform<TCipher> : IDisposable where TCipher : class, IDataUnitCipher<TCipher>
{
	private const int TweakLength = 16;
	private const int PreferredChunkSize = 64 * 1024;

	private readonly IPositionalStorage _storage;
	private readonly TCipher _cipher;
	private readonly UInt128 _firstDataUnitNumber;
	private readonly int _chunkSize;
	private readonly long _maxLength;

	/// <summary>
	/// Validates the arguments shared by the public constructors and creates the transform.
	/// </summary>
	/// <param name="storage">The backend.</param>
	/// <param name="cipher">The cipher.</param>
	/// <param name="dataUnitSize">The data unit size, in bytes.</param>
	/// <param name="firstDataUnitNumber">The data unit number of the data unit at offset zero.</param>
	/// <param name="storageParamName">The public parameter that supplied <paramref name="storage" />.</param>
	public DataUnitTransform(IPositionalStorage storage, TCipher cipher, int dataUnitSize, UInt128 firstDataUnitNumber, string storageParamName)
	{
		ArgumentNullException.ThrowIfNull(cipher);

		if (TCipher.TweakSize is not TweakLength)
		{
			throw new ArgumentException("The cipher must use a 16-byte tweak.", nameof(cipher));
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(dataUnitSize, TweakLength);

		if (storage.GetLength() % dataUnitSize is not 0)
		{
			throw new ArgumentException("The existing data must be a whole number of data units.", storageParamName);
		}

		_storage = storage;
		_cipher = cipher;
		DataUnitSize = dataUnitSize;
		_firstDataUnitNumber = firstDataUnitNumber;
		_chunkSize = GetChunkSize(dataUnitSize);
		_maxLength = GetMaxLength(dataUnitSize, firstDataUnitNumber);
	}

	/// <summary>
	/// Gets the data unit size, in bytes.
	/// </summary>
	public int DataUnitSize { get; }

	/// <summary>
	/// Gets the most bytes moved per backend call: 64 KiB rounded down to whole data units, but at least one data unit.
	/// </summary>
	public static int GetChunkSize(int dataUnitSize)
	{
		return Math.Max(dataUnitSize, PreferredChunkSize / dataUnitSize * dataUnitSize);
	}

	/// <summary>
	/// Disposes the cipher.
	/// </summary>
	public void Dispose()
	{
		_cipher.Dispose();
	}

	public long GetLength()
	{
		return _storage.GetLength();
	}

	public void SetLength(long length, [CallerArgumentExpression(nameof(length))] string? paramName = null)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(length, paramName);

		if (length % DataUnitSize is not 0)
		{
			throw new ArgumentException("The length must be a multiple of the data unit size.", paramName);
		}

		long currentLength = GetValidatedLength();

		if (length < currentLength)
		{
			_storage.SetLength(length);
		}
		else if (length > currentLength)
		{
			if (length > _maxLength)
			{
				ThrowPastMaxLength();
			}

			WriteUnits(new WritePlan(currentLength, length, currentLength, null, null), ReadOnlySpan<byte>.Empty, length);
		}
	}

	public int Read(Span<byte> buffer, long offset)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(offset);

		int count = GetReadCount(buffer.Length, offset);
		buffer = buffer.Slice(0, count);
		byte[]? scratch = null;

		try
		{
			while (!buffer.IsEmpty)
			{
				int unitOffset = (int)(offset % DataUnitSize);
				int transferred;

				if (unitOffset is 0 && buffer.Length >= DataUnitSize)
				{
					Span<byte> units = buffer.Slice(0, GetAlignedLength(buffer.Length));
					ReadExactly(units, offset);
					DecryptUnits(units, offset);
					transferred = units.Length;
				}
				else
				{
					scratch ??= ArrayPool<byte>.Shared.Rent(DataUnitSize);
					Span<byte> unit = scratch.AsSpan(0, DataUnitSize);
					long unitStart = offset - unitOffset;
					ReadExactly(unit, unitStart);
					DecryptUnits(unit, unitStart);
					transferred = Math.Min(DataUnitSize - unitOffset, buffer.Length);
					unit.Slice(unitOffset, transferred).CopyTo(buffer);
				}

				buffer = buffer.Slice(transferred);
				offset += transferred;
			}

			return count;
		}
		finally
		{
			ReturnCleared(scratch);
		}
	}

	public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(offset);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<int>(cancellationToken);
		}

		return ReadCoreAsync(buffer, offset, cancellationToken);
	}

	public void Write(ReadOnlySpan<byte> buffer, long offset)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(offset);

		if (buffer.IsEmpty)
		{
			return;
		}

		WriteUnits(PlanWrite(offset, buffer.Length), buffer, offset);
	}

	/// <summary>
	/// Writes the whole data unit <paramref name="unit" /> at <paramref name="offset" />, encrypting it into <paramref name="ciphertext" /> unless a gap precedes it.
	/// </summary>
	/// <remarks><paramref name="unit" /> stays unchanged. <paramref name="ciphertext" />, a data unit that must not overlap it, is cleared if the write fails.</remarks>
	public void WriteUnit(ReadOnlySpan<byte> unit, Span<byte> ciphertext, long offset)
	{
		if (offset > GetValidatedLength())
		{
			Write(unit, offset);
			return;
		}

		try
		{
			EncryptUnit(unit, ciphertext, offset);
			_storage.Write(ciphertext, offset);
		}
		catch
		{
			// A failed encryption may leave plaintext in it.
			CryptographicOperations.ZeroMemory(ciphertext);
			throw;
		}
	}

	/// <inheritdoc cref="WriteUnit" />
	public async ValueTask WriteUnitAsync(ReadOnlyMemory<byte> unit, Memory<byte> ciphertext, long offset, CancellationToken cancellationToken)
	{
		if (offset > GetValidatedLength())
		{
			await WriteAsync(unit, offset, cancellationToken).ConfigureAwait(false);
			return;
		}

		try
		{
			EncryptUnit(unit.Span, ciphertext.Span, offset);
			await _storage.WriteAsync(ciphertext, offset, cancellationToken).ConfigureAwait(false);
		}
		catch
		{
			CryptographicOperations.ZeroMemory(ciphertext.Span);
			throw;
		}
	}

	/// <summary>
	/// Throws when <paramref name="count" /> bytes at <paramref name="offset" /> would end past the last data unit that has a data unit number and ends within <see cref="long.MaxValue" />.
	/// </summary>
	public void ValidateRange(long offset, int count)
	{
		if (offset > _maxLength - count)
		{
			ThrowPastMaxLength();
		}
	}

	public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(offset);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled(cancellationToken);
		}

		if (buffer.IsEmpty)
		{
			return ValueTask.CompletedTask;
		}

		return WriteCoreAsync(buffer, offset, cancellationToken);
	}

	private async ValueTask<int> ReadCoreAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		int count = GetReadCount(buffer.Length, offset);
		buffer = buffer.Slice(0, count);
		byte[]? scratch = null;

		try
		{
			while (!buffer.IsEmpty)
			{
				int unitOffset = (int)(offset % DataUnitSize);
				int transferred;

				if (unitOffset is 0 && buffer.Length >= DataUnitSize)
				{
					Memory<byte> units = buffer.Slice(0, GetAlignedLength(buffer.Length));
					await ReadExactlyAsync(units, offset, cancellationToken).ConfigureAwait(false);
					DecryptUnits(units.Span, offset);
					transferred = units.Length;
				}
				else
				{
					scratch ??= ArrayPool<byte>.Shared.Rent(DataUnitSize);
					Memory<byte> unit = scratch.AsMemory(0, DataUnitSize);
					long unitStart = offset - unitOffset;
					await ReadExactlyAsync(unit, unitStart, cancellationToken).ConfigureAwait(false);
					DecryptUnits(unit.Span, unitStart);
					transferred = Math.Min(DataUnitSize - unitOffset, buffer.Length);
					unit.Span.Slice(unitOffset, transferred).CopyTo(buffer.Span);
				}

				buffer = buffer.Slice(transferred);
				offset += transferred;
			}

			return count;
		}
		finally
		{
			ReturnCleared(scratch);
		}
	}

	private async ValueTask WriteCoreAsync(ReadOnlyMemory<byte> source, long offset, CancellationToken cancellationToken)
	{
		WritePlan plan = PlanWrite(offset, source.Length);
		int scratchLength = GetScratchLength(plan);
		byte[] scratch = ArrayPool<byte>.Shared.Rent(scratchLength);

		try
		{
			long windowStart = plan.Start;

			while (windowStart < plan.Stop)
			{
				Memory<byte> window = scratch.AsMemory(0, (int)Math.Min(scratchLength, plan.Stop - windowStart));

				if (TryGetUnitIndex(plan.Head, windowStart, window.Length, out int head))
				{
					await ReadExactlyAsync(window.Slice(head, DataUnitSize), windowStart + head, cancellationToken).ConfigureAwait(false);
				}

				if (TryGetUnitIndex(plan.Tail, windowStart, window.Length, out int tail))
				{
					await ReadExactlyAsync(window.Slice(tail, DataUnitSize), windowStart + tail, cancellationToken).ConfigureAwait(false);
				}

				EncryptWindow(window.Span, windowStart, source.Span, offset, plan.Length);
				await _storage.WriteAsync(window, windowStart, cancellationToken).ConfigureAwait(false);
				windowStart += window.Length;
			}
		}
		catch
		{
			// A failure before the window is encrypted leaves plaintext in it.
			CryptographicOperations.ZeroMemory(scratch.AsSpan(0, scratchLength));
			throw;
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(scratch);
		}
	}

	/// <summary>
	/// Rewrites the data units of <paramref name="plan" /> with <paramref name="source" /> placed at <paramref name="offset" />.
	/// </summary>
	private void WriteUnits(WritePlan plan, ReadOnlySpan<byte> source, long offset)
	{
		int scratchLength = GetScratchLength(plan);
		byte[] scratch = ArrayPool<byte>.Shared.Rent(scratchLength);

		try
		{
			long windowStart = plan.Start;

			while (windowStart < plan.Stop)
			{
				Span<byte> window = scratch.AsSpan(0, (int)Math.Min(scratchLength, plan.Stop - windowStart));

				if (TryGetUnitIndex(plan.Head, windowStart, window.Length, out int head))
				{
					ReadExactly(window.Slice(head, DataUnitSize), windowStart + head);
				}

				if (TryGetUnitIndex(plan.Tail, windowStart, window.Length, out int tail))
				{
					ReadExactly(window.Slice(tail, DataUnitSize), windowStart + tail);
				}

				EncryptWindow(window, windowStart, source, offset, plan.Length);
				_storage.Write(window, windowStart);
				windowStart += window.Length;
			}
		}
		catch
		{
			// A failure before the window is encrypted leaves plaintext in it.
			CryptographicOperations.ZeroMemory(scratch.AsSpan(0, scratchLength));
			throw;
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(scratch);
		}
	}

	/// <summary>
	/// Validates a write of <paramref name="count" /> bytes at <paramref name="offset" /> and plans the data units it rewrites.
	/// </summary>
	private WritePlan PlanWrite(long offset, int count)
	{
		ValidateRange(offset, count);
		long end = offset + count;
		long length = GetValidatedLength();
		long head = offset - offset % DataUnitSize;
		long tail = end - 1 - (end - 1) % DataUnitSize;
		long stop = tail + DataUnitSize;
		bool headIsPartial = offset != head || end < head + DataUnitSize;
		bool tailIsPartial = tail != head && end != stop;

		return new WritePlan(Math.Min(head, length), stop, length, headIsPartial && head < length ? head : null, tailIsPartial && tail < length ? tail : null);
	}

	/// <summary>
	/// Builds the plaintext of the data units in <paramref name="window" /> and encrypts it in place.
	/// </summary>
	/// <remarks>
	/// Units before <paramref name="offset" /> are gap units and become zeros. Units that <paramref name="source" /> covers only partially keep their existing plaintext around it; when they exist below <paramref name="length" />, the window must hold their ciphertext on entry.
	/// </remarks>
	private void EncryptWindow(Span<byte> window, long windowStart, ReadOnlySpan<byte> source, long offset, long length)
	{
		Span<byte> tweak = stackalloc byte[TweakLength];
		UInt128 unitNumber = GetDataUnitNumber(windowStart);
		long end = offset + source.Length;

		for (int i = 0; i < window.Length; i += DataUnitSize, ++unitNumber)
		{
			long unitStart = windowStart + i;
			long from = Math.Max(unitStart, offset);
			long to = Math.Min(unitStart + DataUnitSize, end);
			Span<byte> unit = window.Slice(i, DataUnitSize);
			BinaryPrimitives.WriteUInt128LittleEndian(tweak, unitNumber);

			if (from == unitStart && to == unitStart + DataUnitSize)
			{
				_cipher.Encrypt(tweak, source.Slice((int)(from - offset), DataUnitSize), unit);
				continue;
			}

			if (from < to && unitStart < length)
			{
				_cipher.Decrypt(tweak, unit, unit);
			}
			else
			{
				unit.Clear();
			}

			if (from < to)
			{
				source.Slice((int)(from - offset), (int)(to - from)).CopyTo(unit.Slice((int)(from - unitStart)));
			}

			_cipher.Encrypt(tweak, unit, unit);
		}
	}

	/// <summary>
	/// Validates the backend length and returns how many of <paramref name="requested" /> bytes exist at <paramref name="offset" />.
	/// </summary>
	private int GetReadCount(int requested, long offset)
	{
		long length = GetValidatedLength();

		if (requested is 0 || offset >= length)
		{
			return 0;
		}

		int count = (int)Math.Min(requested, length - offset);
		ValidateRange(offset, count);
		return count;
	}

	private long GetValidatedLength()
	{
		long length = _storage.GetLength();

		if (length % DataUnitSize is not 0)
		{
			ThrowPartialDataUnit();
		}

		return length;
	}

	private int GetAlignedLength(int length)
	{
		return Math.Min(length - length % DataUnitSize, _chunkSize);
	}

	private int GetScratchLength(WritePlan plan)
	{
		return (int)Math.Min(_chunkSize, plan.Stop - plan.Start);
	}

	private static bool TryGetUnitIndex(long? unitStart, long windowStart, int windowLength, out int index)
	{
		if (unitStart - windowStart is { } relative and >= 0 && relative < windowLength)
		{
			index = (int)relative;
			return true;
		}

		index = 0;
		return false;
	}

	private UInt128 GetDataUnitNumber(long offset)
	{
		return checked(_firstDataUnitNumber + (ulong)(offset / DataUnitSize));
	}

	/// <summary>
	/// Gets the largest length whose data units all have a data unit number and end within <see cref="long.MaxValue" />.
	/// </summary>
	private static long GetMaxLength(int dataUnitSize, UInt128 firstDataUnitNumber)
	{
		long maxUnits = long.MaxValue / dataUnitSize;
		UInt128 lastUnitIndex = UInt128.MaxValue - firstDataUnitNumber;
		return (lastUnitIndex < (ulong)maxUnits ? (long)lastUnitIndex + 1 : maxUnits) * dataUnitSize;
	}

	private void EncryptUnit(ReadOnlySpan<byte> unit, Span<byte> ciphertext, long offset)
	{
		Span<byte> tweak = stackalloc byte[TweakLength];
		BinaryPrimitives.WriteUInt128LittleEndian(tweak, GetDataUnitNumber(offset));
		_cipher.Encrypt(tweak, unit, ciphertext);
	}

	private void DecryptUnits(Span<byte> units, long offset)
	{
		Span<byte> tweak = stackalloc byte[TweakLength];
		UInt128 unitNumber = GetDataUnitNumber(offset);

		for (int i = 0; i < units.Length; i += DataUnitSize, ++unitNumber)
		{
			BinaryPrimitives.WriteUInt128LittleEndian(tweak, unitNumber);
			Span<byte> unit = units.Slice(i, DataUnitSize);
			_cipher.Decrypt(tweak, unit, unit);
		}
	}

	private void ReadExactly(Span<byte> buffer, long offset)
	{
		if (!_storage.TryReadExactly(buffer, offset))
		{
			ThrowPartialDataUnit();
		}
	}

	private async ValueTask ReadExactlyAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		if (!await _storage.TryReadExactlyAsync(buffer, offset, cancellationToken).ConfigureAwait(false))
		{
			ThrowPartialDataUnit();
		}
	}

	private void ReturnCleared(byte[]? scratch)
	{
		if (scratch is null)
		{
			return;
		}

		CryptographicOperations.ZeroMemory(scratch.AsSpan(0, DataUnitSize));
		ArrayPool<byte>.Shared.Return(scratch);
	}

	[DoesNotReturn]
	private static void ThrowPastMaxLength()
	{
		throw new OverflowException("The data would extend past the last data unit number or the largest offset.");
	}

	[DoesNotReturn]
	private static void ThrowPartialDataUnit()
	{
		throw new InvalidDataException("The backing storage ends inside a data unit; it is truncated or corrupted.");
	}

	/// <summary>
	/// The whole data units a write rewrites.
	/// </summary>
	/// <param name="Start">The first rewritten unit: the old end when the write leaves a gap, otherwise the first written unit.</param>
	/// <param name="Stop">The end of the last rewritten unit.</param>
	/// <param name="Length">The backend length before the write.</param>
	/// <param name="Head">The first unit if it is written partially and already exists.</param>
	/// <param name="Tail">The last unit if it differs from the first, is written partially and already exists.</param>
	private readonly record struct WritePlan(long Start, long Stop, long Length, long? Head, long? Tail);
}
