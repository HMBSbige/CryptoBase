namespace CryptoBase.Ciphers.Blocks.Aes;

/// <summary>Provides AES with automatic backend selection.</summary>
public sealed class AesCipher : IBlockCipher<AesCipher>
{
	private const int BitsliceBatchSize = AesCipherBitslice.BatchSize;

	private BackendState _state;
	private readonly BitsliceState? _bitslice;

	/// <inheritdoc />
	public static int BlockSize => 16;

	internal ref readonly AesCipherX86 X86 => ref _state.X86;

	internal ref readonly AesCipherArm Arm => ref _state.Arm;

	private AesCipher(ReadOnlySpan<byte> key)
	{
		if (AesCipherX86.IsSupported)
		{
			_state.X86 = AesCipherX86.Create(key);
		}
		else if (AesCipherArm.IsSupported)
		{
			_state.Arm = AesCipherArm.Create(key);
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes = AesCipherVpaes.Create(key);

			// SSSE3 measurements favor VPAES encryption and bitslice decryption batches.
			if (AesCipherBitslice.IsSupported)
			{
				_bitslice = new BitsliceState(key);
			}
		}
		else if (AesCipherBitslice.IsSupported)
		{
			_bitslice = new BitsliceState(key, out _state.Software);
		}
		else
		{
			_state.Software = AesCipherSoftware.Create(key);
		}
	}

	/// <inheritdoc />
	public static AesCipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new AesCipher(key);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (AesCipherX86.IsSupported)
		{
			_state.X86.Dispose();
		}
		else if (AesCipherArm.IsSupported)
		{
			_state.Arm.Dispose();
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes.Dispose();
		}
		else
		{
			_state.Software.Dispose();
		}

		_bitslice?.Cipher.Dispose();
	}

	/// <inheritdoc />
	public void EncryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, BlockSize, nameof(source));
		EncryptBlocks(source, destination);
	}

	/// <inheritdoc />
	public void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, BlockSize);

		if (AesCipherX86.IsSupported)
		{
			AesBlockDriver<AesCipherX86>.EncryptBlocks(ref _state.X86, source, destination);
		}
		else if (AesCipherArm.IsSupported)
		{
			AesBlockDriver<AesCipherArm>.EncryptBlocks(ref _state.Arm, source, destination);
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes.EncryptBlocks(source, destination);
		}
		else
		{
			if (source.Length >= BitsliceBatchSize && _bitslice is not null)
			{
				int length = source.Length & -BitsliceBatchSize;
				_bitslice.Cipher.EncryptBlocks(source.Slice(0, length), destination);
				source = source.Slice(length);
				destination = destination.Slice(length);
			}

			if (!source.IsEmpty)
			{
				_state.Software.EncryptBlocks(source, destination);
			}
		}
	}

	/// <inheritdoc />
	public void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, BlockSize, nameof(source));
		DecryptBlocks(source, destination);
	}

	/// <inheritdoc />
	public void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, BlockSize);

		if (AesCipherX86.IsSupported)
		{
			AesBlockDriver<AesCipherX86>.DecryptBlocks(ref _state.X86, source, destination);
		}
		else if (AesCipherArm.IsSupported)
		{
			AesBlockDriver<AesCipherArm>.DecryptBlocks(ref _state.Arm, source, destination);
		}
		else
		{
			if (source.Length >= BitsliceBatchSize && _bitslice is not null)
			{
				int length = source.Length & -BitsliceBatchSize;
				_bitslice.Cipher.DecryptBlocks(source.Slice(0, length), destination);
				source = source.Slice(length);
				destination = destination.Slice(length);
			}

			if (!source.IsEmpty)
			{
				if (AesCipherVpaes.IsSupported)
				{
					_state.Vpaes.DecryptBlocks(source, destination);
				}
				else
				{
					_state.Software.DecryptBlocks(source, destination);
				}
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal bool TryEncryptXor(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination)
	{
		return TryTransformWithMask(source, mask, destination, false, false);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal bool TryTransformXex(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt)
	{
		return TryTransformWithMask(source, mask, destination, decrypt, true);
	}

	private bool TryTransformWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		if (AesCipherX86.IsSupported)
		{
			AesBlockDriver<AesCipherX86>.TransformWithMask(ref _state.X86, source, mask, destination, decrypt, xorInput);
			return true;
		}

		if (AesCipherArm.IsSupported)
		{
			AesBlockDriver<AesCipherArm>.TransformWithMask(ref _state.Arm, source, mask, destination, decrypt, xorInput);
			return true;
		}

		if (AesCipherVpaes.IsSupported)
		{
			if (decrypt && source.Length >= BitsliceBatchSize && _bitslice is not null)
			{
				int length = source.Length & -BitsliceBatchSize;
				_bitslice.Cipher.TransformWithMask(source.Slice(0, length), mask, destination, true, xorInput);
				source = source.Slice(length);
				mask = mask.Slice(length);
				destination = destination.Slice(length);
			}

			if (!source.IsEmpty)
			{
				_state.Vpaes.TransformWithMask(source, mask, destination, decrypt, xorInput);
			}

			return true;
		}

		if (source.Length >= BitsliceBatchSize && _bitslice is not null)
		{
			int length = source.Length & -BitsliceBatchSize;
			_bitslice.Cipher.TransformWithMask(source.Slice(0, length), mask, destination, decrypt, xorInput);

			if (length < source.Length)
			{
				TransformSoftwareTailWithMask(source.Slice(length), mask.Slice(length), destination.Slice(length), decrypt, xorInput);
			}

			return true;
		}

		return false;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void TransformSoftwareTailWithMask(scoped ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		Span<byte> scratch = stackalloc byte[BitsliceBatchSize - BlockSize];
		scratch = scratch.Slice(0, source.Length);

		try
		{
			if (xorInput)
			{
				FastUtils.Xor(source, mask, scratch, source.Length);
				source = scratch;
			}

			if (decrypt)
			{
				_state.Software.DecryptBlocks(source, scratch);
			}
			else
			{
				_state.Software.EncryptBlocks(source, scratch);
			}

			FastUtils.Xor(scratch, mask, destination, source.Length);
		}
		finally
		{
			scratch.ZeroMemory();
		}
	}

	[StructLayout(LayoutKind.Explicit)]
	private struct BackendState
	{
		[FieldOffset(0)]
		public AesCipherX86 X86;

		[FieldOffset(0)]
		public AesCipherArm Arm;

		[FieldOffset(0)]
		public AesCipherVpaes Vpaes;

		[FieldOffset(0)]
		public AesCipherSoftware Software;
	}

	private sealed class BitsliceState
	{
		public AesCipherBitslice Cipher;

		public BitsliceState(ReadOnlySpan<byte> key)
		{
			Cipher = AesCipherBitslice.Create(key);
		}

		public BitsliceState(ReadOnlySpan<byte> key, out AesCipherSoftware software)
		{
			Span<uint> words = stackalloc uint[60];
			int rounds = AesCipherSoftware.ExpandKey(key, words);
			software = AesCipherSoftware.Create(words, rounds);
			Cipher = AesCipherBitslice.Create(words, rounds);
			words.ZeroMemory();
		}
	}
}
