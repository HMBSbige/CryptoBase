using CryptoBase.Ciphers.Modes.Ctr;
using CryptoBase.Ciphers.Modes.Gcm;
using static CryptoBase.Ciphers.Modes.Gcm.Gcm;

namespace CryptoBase.Ciphers.Modes;

/// <summary>
/// Provides Galois/Counter Mode authenticated encryption for a 16-byte block cipher.
/// </summary>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
public sealed class GcmMode128<TBlockCipher> : IAeadCipher<GcmMode128<TBlockCipher>> where TBlockCipher : IBlockEncryptor<TBlockCipher>
{
	/// <inheritdoc />
	public static GcmMode128<TBlockCipher> Create(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(TBlockCipher.BlockSize, 16);
		TBlockCipher cipher = TBlockCipher.Create(key);

		try
		{
			return new GcmMode128<TBlockCipher>(cipher);
		}
		catch
		{
			cipher.Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	public static int NonceSize => 12;

	/// <inheritdoc />
	public static int TagSize => 16;

	// The tag-mask batch reserves one block for J0 in its 2048-byte key stream buffer.
	private const int MaxTagMaskBatchLength = 2048 - 16;

	private readonly TBlockCipher _blockCipher;
	private GHashKey _hashKey;

	private GcmMode128(TBlockCipher blockCipher)
	{
		_blockCipher = blockCipher;
		Vector128<byte> hashKey = default;

		try
		{
			blockCipher.EncryptBlock(hashKey.AsReadOnlySpan(), hashKey.AsSpan());
			_hashKey = GHashKey.Create(hashKey.AsReadOnlySpan());
		}
		finally
		{
			hashKey.ZeroMemory();
		}
	}

	/// <inheritdoc/>
	public void Encrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData = default)
	{
		if (BlockModeDispatch.TryEncryptGcm(_blockCipher, ref _hashKey, nonce, source, destination, tag, associatedData))
		{
			return;
		}

		EncryptSeparated(nonce, source, destination, tag, associatedData);
	}

	private void EncryptSeparated(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);
		bool associatedDataOverlapsDestination = associatedData.Overlaps(destination);

		Vector128<byte> counter = Begin(nonce, out Vector128<byte> j0);
		GHash hash = GHash.Create(ref _hashKey);

		try
		{
			if (associatedDataOverlapsDestination)
			{
				hash.AppendPaddedSegment(associatedData);
			}

			Vector128<byte> tagMask = default;

			if (BlockModeDispatch.ShouldBatchGcmTagMask(_blockCipher) && !source.IsEmpty)
			{
				TransformWithTagMask(j0, out tagMask, source, destination);
			}
			else
			{
				_blockCipher.EncryptBlock(j0.AsReadOnlySpan(), tagMask.AsSpan());
				int processed = BlockModeDispatch.XorCtr<TBlockCipher, CtrIncrementer32>(_blockCipher, ref counter, source, destination);

				if (processed < source.Length)
				{
					CtrBlocks<TBlockCipher, CtrIncrementer32>.Xor(_blockCipher, ref counter, source.Slice(processed), destination.Slice(processed));
				}
			}

			Vector128<byte> lengthBlock = CreateLengthBlock(associatedData.Length, source.Length);
			Vector128<byte> computedTag = tagMask ^ hash.Finish(associatedDataOverlapsDestination ? ReadOnlySpan<byte>.Empty : associatedData, destination, lengthBlock.AsReadOnlySpan());
			MemoryMarshal.Write(tag, in computedTag);
		}
		finally
		{
			hash.Dispose();
		}
	}

	/// <inheritdoc/>
	public bool TryDecrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		Vector128<byte> counter = Begin(nonce, out Vector128<byte> j0);
		GHash hash = GHash.Create(ref _hashKey);

		try
		{
			if (BlockModeDispatch.ShouldBatchGcmTagMask(_blockCipher) && source.Length is > 0 and <= MaxTagMaskBatchLength)
			{
				return TryDecryptWithTagMask(ref hash, j0, source, tag, destination, associatedData);
			}

			Vector128<byte> tagMask = default;

			_blockCipher.EncryptBlock(j0.AsReadOnlySpan(), tagMask.AsSpan());

			if (!VerifyTag(ref hash, tagMask, associatedData, source, tag))
			{
				destination.ZeroMemory();
				return false;
			}

			int processed = BlockModeDispatch.XorCtr<TBlockCipher, CtrIncrementer32>(_blockCipher, ref counter, source, destination);

			if (processed < source.Length)
			{
				CtrBlocks<TBlockCipher, CtrIncrementer32>.Xor(_blockCipher, ref counter, source.Slice(processed), destination.Slice(processed));
			}

			return true;
		}
		finally
		{
			hash.Dispose();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void TransformWithTagMask(Vector128<byte> j0, out Vector128<byte> tagMask, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(!source.IsEmpty);

		Unsafe.SkipInit(out InlineArray2048<byte> storage);
		Span<byte> keyStream = storage.AsSpan();
		int length = Math.Min(keyStream.Length - 16, source.Length);
		Span<byte> batch = keyStream.Slice(0, (length + 15 & -16) + 16);

		try
		{
			Vector128<byte> counter = j0;
			tagMask = EncryptTagMaskBatch(ref counter, batch);
			FastUtils.Xor(batch.Slice(16), source, destination, length);
			int offset = length;
			offset += BlockModeDispatch.XorCtr<TBlockCipher, CtrIncrementer32>(_blockCipher, ref counter, source.Slice(offset), destination.Slice(offset));

			while (offset < source.Length)
			{
				length = Math.Min(keyStream.Length, source.Length - offset);
				Span<byte> nextBatch = keyStream.Slice(0, length + 15 & -16);
				CtrCounters<CtrIncrementer32>.Fill(ref counter, nextBatch);
				_blockCipher.EncryptBlocks(nextBatch, nextBatch);
				FastUtils.Xor(nextBatch, source.Slice(offset), destination.Slice(offset), length);
				offset += length;
			}
		}
		finally
		{
			// If later batches exist, the first batch already spans the entire buffer.
			batch.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private bool TryDecryptWithTagMask(ref GHash hash, Vector128<byte> j0, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(source.Length is > 0 and <= MaxTagMaskBatchLength);

		Unsafe.SkipInit(out InlineArray2048<byte> storage);
		Span<byte> keyStream = storage.AsSpan();
		Span<byte> batch = keyStream.Slice(0, (source.Length + 15 & -16) + 16);

		try
		{
			Vector128<byte> counter = j0;
			Vector128<byte> tagMask = EncryptTagMaskBatch(ref counter, batch);

			if (!VerifyTag(ref hash, tagMask, associatedData, source, tag))
			{
				destination.ZeroMemory();
				return false;
			}

			FastUtils.Xor(batch.Slice(16), source, destination, source.Length);
			return true;
		}
		finally
		{
			batch.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private Vector128<byte> EncryptTagMaskBatch(ref Vector128<byte> counter, Span<byte> batch)
	{
		CtrCounters<CtrIncrementer32>.Fill(ref counter, batch);
		_blockCipher.EncryptBlocks(batch, batch);
		return Vector128.LoadUnsafe(ref batch.GetReference());
	}

	[SkipLocalsInit]
	private static bool VerifyTag(ref GHash hash, Vector128<byte> tagMask, scoped ReadOnlySpan<byte> associatedData, scoped ReadOnlySpan<byte> ciphertext, scoped ReadOnlySpan<byte> tag)
	{
		Vector128<byte> lengthBlock = CreateLengthBlock(associatedData.Length, ciphertext.Length);
		Vector128<byte> expectedTag = tagMask ^ hash.Finish(associatedData, ciphertext, lengthBlock.AsReadOnlySpan());
		return FixedTime.Equals16(expectedTag.AsReadOnlySpan(), tag);
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		_hashKey.Dispose();
		_blockCipher.Dispose();
	}
}
