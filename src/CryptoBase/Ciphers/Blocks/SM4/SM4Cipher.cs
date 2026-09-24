using AesArm = System.Runtime.Intrinsics.Arm.Aes;
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
		ProcessBlock(_roundKeys, source, destination);
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
		ProcessBlock(_reverseRoundKeys, source, destination);
	}

	/// <inheritdoc />
	public void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);
		ProcessBlocks(_reverseRoundKeys, source, destination);
	}

	private static bool IsVectorized => AdvSimd.Arm64.IsSupported || AesX86.IsSupported && Ssse3.IsSupported;

	private static int MaxBlocks => AesX86.IsSupported && Avx2.IsSupported ? 16 : 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlock(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (IsVectorized)
		{
			ProcessBlocksPadded4(keys, source, destination);
		}
		else
		{
			SM4Utils.ProcessBlock(keys, source, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocks(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (IsVectorized)
		{
			if (source.Length is > 0 and < 64)
			{
				ProcessBlocksPadded4(keys, source, destination);
			}
			else
			{
				ProcessBlocksVector(keys, source, destination);
			}
		}
		else
		{
			ProcessBlocksScalar(ref keys.GetReference(), ref source.GetReference(), ref destination.GetReference(), source.Length);
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksVector(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= MaxBlocks * 16)
		{
			ProcessKernel(MaxBlocks, keys, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += MaxBlocks * 16;
		}

		if (offset < source.Length)
		{
			ProcessBlocksRemainder(keys, source.Slice(offset), destination.Slice(offset));
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksRemainder(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(source.Length > 0 && source.Length < MaxBlocks * 16);

		switch (source.Length)
		{
			case < 64:
			{
				ProcessBlocksPadded4(keys, source, destination);
				break;
			}
			case 64:
			{
				ProcessKernel(4, keys, ref source.GetReference(), ref destination.GetReference());
				break;
			}
			case < 128:
			{
				ProcessBlocksPadded8(keys, source, destination);
				break;
			}
			case 128 when MaxBlocks > 8:
			{
				ProcessKernel(8, keys, ref source.GetReference(), ref destination.GetReference());
				break;
			}
			default:
			{
				ProcessBlocksPadded16(keys, source, destination);
				break;
			}
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksPadded4(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[64]);
		ProcessBlocksPadded(4, keys, source, destination, buffer.Span);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksPadded8(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[128]);
		ProcessBlocksPadded(8, keys, source, destination, buffer.Span);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksPadded16(ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[256]);
		ProcessBlocksPadded(16, keys, source, destination, buffer.Span);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocksPadded(int blocks, ReadOnlySpan<uint> keys, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> scratch)
	{
		Debug.Assert(source.Length > 0 && source.Length % 16 is 0 && source.Length < scratch.Length);
		source.CopyTo(scratch);
		ref byte block = ref scratch.GetReference();
		ProcessKernel(blocks, keys, ref block, ref block);
		scratch.Slice(0, source.Length).CopyTo(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessKernel(int blocks, ReadOnlySpan<uint> keys, ref byte source, ref byte destination)
	{
		Debug.Assert(IsVectorized && (blocks is 4 or 8 || blocks is 16 && MaxBlocks is 16));

		if (AdvSimd.Arm64.IsSupported)
		{
			if (AesArm.IsSupported)
			{
				if (blocks is 4)
				{
					SM4Utils.Process4ArmAes(keys, ref source, ref destination);
				}
				else
				{
					SM4Utils.Process8ArmAes(keys, ref source, ref destination);
				}
			}
			else if (blocks is 4)
			{
				SM4Utils.Process4Neon(keys, ref source, ref destination);
			}
			else
			{
				SM4Utils.Process8Neon(keys, ref source, ref destination);
			}
		}
		else if (blocks is 4)
		{
			SM4Utils.Process4V128(keys, ref source, ref destination);
		}
		else if (!Avx2.IsSupported)
		{
			SM4Utils.Process8V128(keys, ref source, ref destination);
		}
		else if (blocks is 8)
		{
			SM4Utils.Process8V256(keys, ref source, ref destination);
		}
		else
		{
			SM4Utils.Process16V256(keys, ref source, ref destination);
		}
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
