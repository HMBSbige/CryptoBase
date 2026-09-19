using CryptoBase.Ciphers.Modes.Gcm;

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

	private readonly TBlockCipher _blockCipher;
	private Vector128<byte> _hashKey;

	private GcmMode128(TBlockCipher blockCipher)
	{
		_blockCipher = blockCipher;
		_hashKey = default;
		blockCipher.EncryptBlock(_hashKey.AsReadOnlySpan(), _hashKey.AsSpan());
	}

	/// <inheritdoc/>
	public void Encrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);
		bool associatedDataOverlapsDestination = associatedData.Overlaps(destination);

		Vector128<byte> counter = CreateCounter(nonce);
		Vector128<byte> tagBuffer = default;
		GHash hash = GHash.Create(_hashKey.AsReadOnlySpan());

		try
		{
			_blockCipher.EncryptBlock(counter.AsReadOnlySpan(), tagBuffer.AsSpan());
			counter = counter.WithElement(15, (byte)2);

			if (associatedDataOverlapsDestination)
			{
				hash.AppendPaddedSegment(associatedData);
			}

			Transform(ref counter, source, destination);
			tagBuffer ^= ComputeHash(ref hash, associatedDataOverlapsDestination ? ReadOnlySpan<byte>.Empty : associatedData, destination, associatedData.Length);
			MemoryMarshal.Write(tag, in tagBuffer);
		}
		finally
		{
			hash.ZeroMemory();
		}
	}

	/// <inheritdoc/>
	public bool TryDecrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		Vector128<byte> counter = CreateCounter(nonce);
		Vector128<byte> tagBuffer = default;
		GHash hash = GHash.Create(_hashKey.AsReadOnlySpan());

		try
		{
			_blockCipher.EncryptBlock(counter.AsReadOnlySpan(), tagBuffer.AsSpan());
			counter = counter.WithElement(15, (byte)2);
			tagBuffer ^= ComputeHash(ref hash, associatedData, source, associatedData.Length);

			if (!FixedTime.Equals16(tagBuffer.AsReadOnlySpan(), tag))
			{
				destination.ZeroMemory();
				return false;
			}

			Transform(ref counter, source, destination);
			return true;
		}
		finally
		{
			hash.ZeroMemory();
		}
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		_hashKey.ZeroMemory();
		_blockCipher.Dispose();
	}

	private static Vector128<byte> CreateCounter(ReadOnlySpan<byte> nonce)
	{
		Vector128<byte> counter = default;
		nonce.CopyTo(counter.AsSpan());
		counter = counter.WithElement(15, (byte)1);
		return counter;
	}

	private static Vector128<byte> ComputeHash(ref GHash hash, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, int associatedDataLength)
	{
		Vector128<byte> buffer = default;
		BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(), (ulong)associatedDataLength << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan().Slice(8), (ulong)ciphertext.Length << 3);
		hash.HashPaddedSegmentsAndReset(associatedData, ciphertext, buffer.AsReadOnlySpan(), buffer.AsSpan());
		return buffer;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private void Transform(ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = source.Length >= 16
			? CtrBlocks<TBlockCipher, CtrIncrementer32>.XorBlocks(_blockCipher, ref counter, source, destination)
			: 0;
		int left = source.Length - processed;

		if (left is 0)
		{
			return;
		}

		CtrBlocks<TBlockCipher, CtrIncrementer32>.XorFinalBlock(_blockCipher, ref counter, source.Slice(processed), destination.Slice(processed));
	}
}
