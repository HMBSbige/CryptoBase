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

	[MethodImpl(MethodImplOptions.NoInlining)]
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
	internal bool TryTransform<TPolicy, TOperation>(ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy where TOperation : struct, IAesOperation
	{
		if (AesCipherX86.IsSupported)
		{
			AesBlockDriver<AesCipherX86>.Transform<TPolicy, TOperation>(ref _state.X86, ref state, source, destination);
			return true;
		}

		if (AesCipherArm.IsSupported)
		{
			AesBlockDriver<AesCipherArm>.Transform<TPolicy, TOperation>(ref _state.Arm, ref state, source, destination);
			return true;
		}

		return false;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal bool TryEncryptXor(ReadOnlySpan<byte> counters, ReadOnlySpan<byte> data, Span<byte> destination)
	{
		AesOutputMaskPolicy policy = new(data);
		return TryEncryptWithPolicy(ref policy, counters, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal bool TryEncryptXex(ReadOnlySpan<byte> source, ReadOnlySpan<byte> tweaks, Span<byte> destination)
	{
		AesInputOutputMaskPolicy policy = new(tweaks);
		return TryEncryptWithPolicy(ref policy, source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal bool TryDecryptXex(ReadOnlySpan<byte> source, ReadOnlySpan<byte> tweaks, Span<byte> destination)
	{
		AesInputOutputMaskPolicy policy = new(tweaks);
		return TryDecryptWithPolicy(ref policy, source, destination);
	}

	private bool TryEncryptWithPolicy<TPolicy>(ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		if (TryTransformVector<TPolicy, AesEncrypt>(ref policy, source, destination))
		{
			return true;
		}

		if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes.TransformWithPolicy<TPolicy, AesEncrypt>(ref policy, source, destination);
			return true;
		}

		if (source.Length >= BitsliceBatchSize && _bitslice is not null)
		{
			TransformBitslice<TPolicy, AesEncrypt>(ref policy, source, destination);
			return true;
		}

		return false;
	}

	private bool TryDecryptWithPolicy<TPolicy>(ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		if (TryTransformVector<TPolicy, AesDecrypt>(ref policy, source, destination))
		{
			return true;
		}

		if (source.Length >= BitsliceBatchSize && _bitslice is not null)
		{
			TransformBitslice<TPolicy, AesDecrypt>(ref policy, source, destination);
			return true;
		}

		if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes.TransformWithPolicy<TPolicy, AesDecrypt>(ref policy, source, destination);
			return true;
		}

		return false;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryTransformVector<TPolicy, TOperation>(ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TOperation : struct, IAesOperation
	{
		if (AesCipherX86.IsSupported)
		{
			AesBlockDriver<AesCipherX86>.TransformWithPolicy<TPolicy, TOperation>(ref _state.X86, ref policy, source, destination);
			return true;
		}

		if (AesCipherArm.IsSupported)
		{
			AesBlockDriver<AesCipherArm>.TransformWithPolicy<TPolicy, TOperation>(ref _state.Arm, ref policy, source, destination);
			return true;
		}

		return false;
	}

	private void TransformBitslice<TPolicy, TOperation>(ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TOperation : struct, IAesOperation
	{
		Debug.Assert(_bitslice is not null);
		int length = source.Length & -BitsliceBatchSize;
		_bitslice.Cipher.TransformWithPolicy<TPolicy, TOperation>(ref policy, source.Slice(0, length), destination);

		if (length < source.Length)
		{
			TransformTail<TPolicy, TOperation>(ref policy, source, destination, length);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void TransformTail<TPolicy, TOperation>(ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination, int offset) where TPolicy : struct, IAesModePolicy, allows ref struct where TOperation : struct, IAesOperation
	{
		if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes.TransformWithPolicy<TPolicy, TOperation>(ref policy, source, destination, offset);
			return;
		}

		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int length = source.Length - offset;
		Span<byte> scratch = stackalloc byte[BitsliceBatchSize - BlockSize];
		scratch = scratch.Slice(0, length);

		try
		{
			for (int i = 0; i < length; i += BlockSize)
			{
				policy.Prepare1(ref src, (nuint)(offset + i)).StoreUnsafe(ref scratch.GetReference(), (nuint)i);
			}

			TOperation.ApplyBlocks(in _state.Software, scratch, scratch);

			for (int i = 0; i < length; i += BlockSize)
			{
				policy.Finish1(ref src, ref dst, (nuint)(offset + i), Vector128.LoadUnsafe(ref scratch.GetReference(), (nuint)i));
			}
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
