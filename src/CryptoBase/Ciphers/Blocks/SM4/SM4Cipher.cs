using AesX86 = System.Runtime.Intrinsics.X86.Aes;

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
		SM4Utils.InitRoundKeys(ref key.GetReference(), ref _roundKeys[0]);
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
		SM4Utils.ProcessBlock(_roundKeys, source, destination);
	}

	/// <inheritdoc />
	public void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);
		ProcessBlocks(_roundKeys, source, destination);
	}

	/// <inheritdoc />
	public void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		CipherBufferGuard.Output(source, destination);
		SM4Utils.ProcessBlock(_reverseRoundKeys, source, destination);
	}

	/// <inheritdoc />
	public void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);
		ProcessBlocks(_reverseRoundKeys, source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocks(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && source.Length >= 128 && (Avx2.IsSupported || Ssse3.IsSupported))
		{
			ProcessBlocksVector(keys, source, destination);
			return;
		}

		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		if (AesX86.IsSupported && Ssse3.IsSupported && source.Length >= 64)
		{
			ProcessBlocks4(keys, ref src, ref dst);
			offset = 64;
		}

		if (offset < source.Length)
		{
			ProcessBlocksScalar(ref keys.GetReference(), ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), source.Length - offset);
		}
	}

	private static void ProcessBlocksVector(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			while (source.Length - offset >= 256)
			{
				SM4Utils.Process16V256(keys, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
				offset += 256;
			}

			while (source.Length - offset >= 128)
			{
				SM4Utils.Process8V256(keys, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
				offset += 128;
			}
		}

		if (AesX86.IsSupported && Ssse3.IsSupported)
		{
			while (source.Length - offset >= 128)
			{
				SM4Utils.Process8V128(keys, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
				offset += 128;
			}

			while (source.Length - offset >= 64)
			{
				SM4Utils.Process4V128(keys, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
				offset += 64;
			}
		}

		while (offset < source.Length)
		{
			SM4Utils.ProcessBlock(keys, source.Slice(offset, 16), destination.Slice(offset, 16));
			offset += 16;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocks4(ReadOnlySpan<uint> keys, ref byte source, ref byte destination)
	{
		SM4Utils.Process4V128(keys, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksScalar(ref uint keys, ref byte source, ref byte destination, int length)
	{
		ReadOnlySpan<uint> keySpan = MemoryMarshal.CreateReadOnlySpan(ref keys, 32);
		ReadOnlySpan<byte> sourceSpan = MemoryMarshal.CreateReadOnlySpan(ref source, length);
		Span<byte> destinationSpan = MemoryMarshal.CreateSpan(ref destination, length);

		for (int offset = 0; offset < length; offset += 16)
		{
			SM4Utils.ProcessBlock(keySpan, sourceSpan.Slice(offset, 16), destinationSpan.Slice(offset, 16));
		}
	}
}
