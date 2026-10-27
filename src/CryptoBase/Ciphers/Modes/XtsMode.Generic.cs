using CryptoBase.Ciphers.Modes.Xts;

namespace CryptoBase.Ciphers.Modes;

/// <summary>Provides XTS with ciphertext stealing for data units of at least 16 bytes.</summary>
public sealed class XtsMode<TBlockCipher> : IDataUnitCipher<XtsMode<TBlockCipher>> where TBlockCipher : IBlockCipher<TBlockCipher>
{
	private const int BlockSize = 16;

	// Not readonly: readonly fields would make Dispose run on defensive copies when TBlockCipher is a struct.
	private TBlockCipher _dataCipher;
	private TBlockCipher _tweakCipher;

	/// <inheritdoc />
	public static int TweakSize => BlockSize;

	/// <summary>Initializes the cipher with the supplied block cipher instances.</summary>
	private XtsMode(TBlockCipher dataCipher, TBlockCipher tweakCipher)
	{
		_dataCipher = dataCipher;
		_tweakCipher = tweakCipher;
	}

	/// <summary>Creates XTS from the concatenated data and tweak keys.</summary>
	public static XtsMode<TBlockCipher> Create(scoped ReadOnlySpan<byte> key)
	{
		if (key.Length is 0 || key.Length % 2 is not 0)
		{
			throw new ArgumentException("XTS requires two equally sized keys.", nameof(key));
		}

		return Create(key.Slice(0, key.Length / 2), key.Slice(key.Length / 2));
	}

	/// <summary>Creates XTS from equally sized data and tweak keys.</summary>
	public static XtsMode<TBlockCipher> Create(scoped ReadOnlySpan<byte> dataKey, scoped ReadOnlySpan<byte> tweakKey)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(TBlockCipher.BlockSize, BlockSize);
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataKey.Length, tweakKey.Length, nameof(tweakKey));
		TBlockCipher data = TBlockCipher.Create(dataKey);

		try
		{
			return new XtsMode<TBlockCipher>(data, TBlockCipher.Create(tweakKey));
		}
		catch
		{
			data.Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_dataCipher.Dispose();
		_tweakCipher.Dispose();
	}

	/// <inheritdoc />
	public void Encrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		Transform<Encryption>(tweak, source, destination);
	}

	/// <inheritdoc />
	public void Decrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		Transform<Decryption>(tweak, source, destination);
	}

	private void Transform<TDirection>(ReadOnlySpan<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination) where TDirection : struct, IBlockDirection
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweak.Length, BlockSize, nameof(tweak));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		CipherBufferGuard.Output(source, destination);
		Vector128<byte> tweakBlock = default;
		_tweakCipher.EncryptBlock(tweak, tweakBlock.AsSpan());
		int tail = source.Length % BlockSize;
		int fullLength = tail is 0 ? source.Length : source.Length - tail - BlockSize;
		bool stealingBlockTransformed = false;

		if (fullLength is not 0)
		{
			ReadOnlySpan<byte> fullSource = source.Slice(0, fullLength);

			if (!BlockModeDispatch.TryTransformXts<TBlockCipher, TDirection>(_dataCipher, ref tweakBlock, fullSource, destination))
			{
				TransformBuffered<TDirection>(ref tweakBlock, source.Slice(0, source.Length - tail), destination, TDirection.IsDecrypt && tail is not 0);
				stealingBlockTransformed = tail is not 0;
			}
		}

		if (tail is not 0)
		{
			TransformTail<TDirection>(tweakBlock, source.Slice(fullLength), destination.Slice(fullLength), tail, stealingBlockTransformed);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void TransformBuffered<TDirection>(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, bool swapLastTweak) where TDirection : struct, IBlockDirection
	{
		Unsafe.SkipInit(out InlineArray2048<byte> storage);
		Span<byte> tweaks = storage.AsSpan();

		try
		{
			Vector128<byte> currentTweak = tweak;
			int offset = 0;

			while (offset < source.Length)
			{
				int length = Math.Min(tweaks.Length, source.Length - offset);
				XtsTweak.Fill(ref currentTweak, tweaks.Slice(0, length));

				if (swapLastTweak && offset + length == source.Length)
				{
					Vector128<byte> lastTweak = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(tweaks), (nuint)(length - BlockSize));
					currentTweak.StoreUnsafe(ref MemoryMarshal.GetReference(tweaks), (nuint)(length - BlockSize));
					currentTweak = lastTweak;
				}

				Span<byte> buffer = destination.Slice(offset, length);

				if (!BlockModeDispatch.TryTransformXex<TBlockCipher, TDirection>(_dataCipher, source.Slice(offset, length), tweaks, buffer))
				{
					FastUtils.Xor(tweaks, source.Slice(offset), buffer, length);

					if (TDirection.IsDecrypt)
					{
						_dataCipher.DecryptBlocks(buffer, buffer);
					}
					else
					{
						_dataCipher.EncryptBlocks(buffer, buffer);
					}

					FastUtils.Xor(tweaks, buffer, buffer, length);
				}

				offset += length;
			}

			tweak = currentTweak;
		}
		finally
		{
			tweaks.Slice(0, Math.Min(tweaks.Length, source.Length)).ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private void TransformTail<TDirection>(Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int tail, bool stealingBlockTransformed) where TDirection : struct, IBlockDirection
	{
		Debug.Assert(source.Length == BlockSize + tail && destination.Length >= source.Length);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref byte output = ref MemoryMarshal.GetReference(destination);
		Vector128<byte> last;

		if (stealingBlockTransformed)
		{
			last = Vector128.LoadUnsafe(ref output);
		}
		else
		{
			Vector128<byte> next = XtsTweak.MultiplyByAlpha(tweak);
			last = TransformBlock<TDirection>(TDirection.IsDecrypt ? next : tweak, Vector128.LoadUnsafe(ref input));
			tweak = TDirection.IsDecrypt ? tweak : next;
		}

		// In place, the stolen bytes overwrite the partial block, so read it first.
		Vector128<byte> partial = Vector128.LoadPartialUnsafe(ref input, BlockSize, tail);
		last.StorePartialUnsafe(ref output, BlockSize, tail);
		Vector128<byte> mask = Vector128.LessThan(Vector128<sbyte>.Indices, Vector128.Create((sbyte)tail)).AsByte();
		TransformBlock<TDirection>(tweak, Vector128.ConditionalSelect(mask, partial, last)).StoreUnsafe(ref output);
	}

	private Vector128<byte> TransformBlock<TDirection>(Vector128<byte> tweak, Vector128<byte> block) where TDirection : struct, IBlockDirection
	{
		return BlockModeDispatch.TransformBlock<TBlockCipher, TDirection>(_dataCipher, block ^ tweak) ^ tweak;
	}
}
