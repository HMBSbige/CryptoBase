namespace CryptoBase.Ciphers.Blocks.Aes;

/// <summary>Provides AES with automatic backend selection.</summary>
public sealed class AesCipher : IBlockCipher<AesCipher>
{
	/// <inheritdoc />
	public static int BlockSize => 16;

	private BackendState _state;
	private readonly BitsliceState? _bitslice;
	private const int BitsliceBatchSize = AesCipherBitslice.BatchSize;
	internal const byte Rcon0 = 0x00;
	internal const byte Rcon1 = 0x01;
	internal const byte Rcon2 = 0x02;
	internal const byte Rcon3 = 0x04;
	internal const byte Rcon4 = 0x08;
	internal const byte Rcon5 = 0x10;
	internal const byte Rcon6 = 0x20;
	internal const byte Rcon7 = 0x40;
	internal const byte Rcon8 = 0x80;
	internal const byte Rcon9 = 0x1b;
	internal const byte Rcon10 = 0x36;

	internal static ReadOnlySpan<byte> Rcon => [Rcon0, Rcon1, Rcon2, Rcon3, Rcon4, Rcon5, Rcon6, Rcon7, Rcon8, Rcon9, Rcon10];

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
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		EncryptBlocks(source, destination);
	}

	/// <inheritdoc />
	public void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);

		if (AesCipherX86.IsSupported)
		{
			_state.X86.EncryptBlocks(source, destination);
		}
		else if (AesCipherArm.IsSupported)
		{
			_state.Arm.EncryptBlocks(source, destination);
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_state.Vpaes.EncryptBlocks(source, destination);
		}
		else
		{
			if (source.Length >= BitsliceBatchSize && _bitslice is { } bitslice)
			{
				int length = source.Length & -BitsliceBatchSize;
				bitslice.Cipher.EncryptBlocks(source.Slice(0, length), destination);
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
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		DecryptBlocks(source, destination);
	}

	/// <inheritdoc />
	public void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);

		if (AesCipherX86.IsSupported)
		{
			_state.X86.DecryptBlocks(source, destination);
		}
		else if (AesCipherArm.IsSupported)
		{
			_state.Arm.DecryptBlocks(source, destination);
		}
		else
		{
			if (source.Length >= BitsliceBatchSize && _bitslice is { } bitslice)
			{
				int length = source.Length & -BitsliceBatchSize;
				bitslice.Cipher.DecryptBlocks(source.Slice(0, length), destination);
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

	internal bool TryTransformWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		if (AesCipherX86.IsSupported)
		{
			_state.X86.TransformWithMask(source, mask, destination, decrypt, xorInput);
			return true;
		}

		if (AesCipherArm.IsSupported)
		{
			_state.Arm.TransformWithMask(source, mask, destination, decrypt, xorInput);
			return true;
		}

		if (AesCipherVpaes.IsSupported)
		{
			if (decrypt && source.Length >= BitsliceBatchSize && _bitslice is { } bitslice)
			{
				int length = source.Length & -BitsliceBatchSize;
				bitslice.Cipher.TransformWithMask(source.Slice(0, length), mask, destination, true, xorInput);
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

		if (source.Length >= BitsliceBatchSize && _bitslice is { } softwareBitslice)
		{
			int length = source.Length & -BitsliceBatchSize;
			softwareBitslice.Cipher.TransformWithMask(source.Slice(0, length), mask, destination, decrypt, xorInput);

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
