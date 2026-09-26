namespace CryptoBase.Ciphers.Blocks.SM4;

/// <summary>Provides SM4 with automatic backend selection.</summary>
public sealed class SM4Cipher : IBlockCipher<SM4Cipher>
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = 16;

	[InlineArray(32)]
	private struct RoundKeys
	{
		private uint _element0;
	}

	private RoundKeys _roundKeys;
	private RoundKeys _reverseRoundKeys;

	/// <inheritdoc />
	public static int BlockSize => 16;

	private SM4Cipher(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		SM4KeySchedule.InitRoundKeys(ref key.GetReference(), ref _roundKeys[0]);
		((ReadOnlySpan<uint>)_roundKeys).CopyTo(_reverseRoundKeys);
		((Span<uint>)_reverseRoundKeys).Reverse();
	}

	/// <inheritdoc />
	public static SM4Cipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new SM4Cipher(key);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_roundKeys.ZeroMemory();
		_reverseRoundKeys.ZeroMemory();
	}

	/// <inheritdoc />
	public void EncryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		CipherBufferGuard.Output(source, destination);
		ProcessBlocks(ref _roundKeys[0], source, destination, true);
	}

	/// <inheritdoc />
	public void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);
		ProcessBlocks(ref _roundKeys[0], source, destination, false);
	}

	/// <inheritdoc />
	public void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		CipherBufferGuard.Output(source, destination);
		ProcessBlocks(ref _reverseRoundKeys[0], source, destination, true);
	}

	/// <inheritdoc />
	public void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);
		ProcessBlocks(ref _reverseRoundKeys[0], source, destination, false);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocks(ref uint rk, ReadOnlySpan<byte> source, Span<byte> destination, bool singleBlock)
	{
		if (SM4ArmAes.IsSupported)
		{
			SM4BlockDriver<SM4ArmAes>.ProcessBlocks(ref rk, source, destination, singleBlock);
		}
		else if (SM4Neon.IsSupported)
		{
			SM4BlockDriver<SM4Neon>.ProcessBlocks(ref rk, source, destination, singleBlock);
		}
		else if (SM4Gfni.IsSupported)
		{
			SM4BlockDriver<SM4Gfni>.ProcessBlocks(ref rk, source, destination, singleBlock);
		}
		else if (SM4AesNI.IsSupported)
		{
			SM4BlockDriver<SM4AesNI>.ProcessBlocks(ref rk, source, destination, singleBlock);
		}
		else
		{
			SM4Scalar.ProcessBlocks(ref rk, source, destination);
		}
	}
}
