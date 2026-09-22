using CryptoBase.Ciphers.Streams;
using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Aead;

internal static class ChaCha20Poly1305Utils
{
	internal static void EncryptAndComputeTag(ChaCha20Cipher chacha20, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		EncryptAndComputeTag(new ChaCha20Adapter(chacha20), source, destination, tag, associatedData);
	}

	internal static void EncryptAndComputeTag(XChaCha20Cipher chacha20, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		EncryptAndComputeTag(new XChaCha20Adapter(chacha20), source, destination, tag, associatedData);
	}

	[SkipLocalsInit]
	private static void EncryptAndComputeTag<TCipher>(TCipher cipher, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData) where TCipher : struct, IChaCha20Poly1305Cipher<TCipher>
	{
		Debug.Assert(tag.Length == Poly1305Algorithm.MacLength);

		using CryptoBuffer<byte> poly1305Key = new(stackalloc byte[Poly1305Algorithm.KeyLengthInBytes]);
		Span<byte> lengthBlock = stackalloc byte[Poly1305Algorithm.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.Slice(8), (ulong)source.Length);

		TCipher.DerivePoly1305Key(cipher, poly1305Key.Span);

		if (Poly1305Algorithm.ShouldUseAvx512(associatedData.Length, source.Length, lengthBlock.Length))
		{
			EncryptAndComputeTagCore<TCipher, Poly1305Avx512>(cipher, poly1305Key.Span, source, destination, tag, associatedData, lengthBlock);
			return;
		}

		if (Poly1305Algorithm.ShouldUseAvx2(associatedData.Length, source.Length, lengthBlock.Length))
		{
			EncryptAndComputeTagCore<TCipher, Poly1305Avx2>(cipher, poly1305Key.Span, source, destination, tag, associatedData, lengthBlock);
			return;
		}

		if (Poly1305Algorithm.ShouldUseSse2(associatedData.Length, source.Length, lengthBlock.Length))
		{
			EncryptAndComputeTagCore<TCipher, Poly1305Sse2>(cipher, poly1305Key.Span, source, destination, tag, associatedData, lengthBlock);
			return;
		}

		if (Poly1305Algorithm.ShouldUseAdvSimd(associatedData.Length, source.Length, lengthBlock.Length))
		{
			EncryptAndComputeTagCore<TCipher, Poly1305AdvSimd>(cipher, poly1305Key.Span, source, destination, tag, associatedData, lengthBlock);
			return;
		}

		EncryptAndComputeTagCore<TCipher, Poly1305Software>(cipher, poly1305Key.Span, source, destination, tag, associatedData, lengthBlock);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void EncryptAndComputeTagCore<TCipher, TState>(TCipher cipher, ReadOnlySpan<byte> poly1305Key, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> lengthBlock)
		where TCipher : struct, IChaCha20Poly1305Cipher<TCipher>
		where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Unsafe.SkipInit(out TState state);
		TState.Initialize(ref state, poly1305Key);

		try
		{
			state.AppendPaddedSegment(associatedData);
			TCipher.SetCounter(cipher, 1);
			TCipher.Xor(cipher, source, destination);
			state.AppendPaddedSegment(destination);
			state.AppendPaddedSegment(lengthBlock);
			state.WriteMac(tag);
		}
		finally
		{
			state.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryDecrypt(ChaCha20Cipher chacha20, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData, Span<byte> computedTag)
	{
		return TryDecrypt(new ChaCha20Adapter(chacha20), source, tag, destination, associatedData, computedTag);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryDecrypt(XChaCha20Cipher chacha20, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData, Span<byte> computedTag)
	{
		return TryDecrypt(new XChaCha20Adapter(chacha20), source, tag, destination, associatedData, computedTag);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecrypt<TCipher>(TCipher cipher, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData, Span<byte> computedTag) where TCipher : struct, IChaCha20Poly1305Cipher<TCipher>
	{
		ComputeTag(cipher, associatedData, source, computedTag);

		if (!FixedTime.Equals16(computedTag, tag))
		{
			destination.ZeroMemory();
			return false;
		}

		TCipher.SetCounter(cipher, 1);
		TCipher.Xor(cipher, source, destination);
		return true;
	}

	[SkipLocalsInit]
	private static void ComputeTag<TCipher>(TCipher cipher, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> tag) where TCipher : struct, IChaCha20Poly1305Cipher<TCipher>
	{
		Debug.Assert(tag.Length == Poly1305Algorithm.MacLength);

		using CryptoBuffer<byte> poly1305Key = new(stackalloc byte[Poly1305Algorithm.KeyLengthInBytes]);
		TCipher.DerivePoly1305Key(cipher, poly1305Key.Span);

		Span<byte> lengthBlock = stackalloc byte[Poly1305Algorithm.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.Slice(8), (ulong)ciphertext.Length);
		Poly1305Algorithm.MacPaddedSegments(poly1305Key.Span, associatedData, ciphertext, lengthBlock, tag);
	}

	private interface IChaCha20Poly1305Cipher<in TSelf> where TSelf : struct, IChaCha20Poly1305Cipher<TSelf>
	{
		static abstract void SetCounter(TSelf cipher, uint counter);

		static abstract void DerivePoly1305Key(TSelf cipher, Span<byte> destination);

		static abstract void Xor(TSelf cipher, ReadOnlySpan<byte> source, Span<byte> destination);
	}

	private readonly struct ChaCha20Adapter : IChaCha20Poly1305Cipher<ChaCha20Adapter>
	{
		private readonly ChaCha20Cipher _cipher;

		internal ChaCha20Adapter(ChaCha20Cipher cipher)
		{
			_cipher = cipher;
		}

		public static void SetCounter(ChaCha20Adapter cipher, uint counter)
		{
			cipher._cipher.SetCounter(counter);
		}

		public static void DerivePoly1305Key(ChaCha20Adapter cipher, Span<byte> destination)
		{
			cipher._cipher.DerivePoly1305Key(destination);
		}

		public static void Xor(ChaCha20Adapter cipher, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			cipher._cipher.Xor(source, destination);
		}
	}

	private readonly struct XChaCha20Adapter : IChaCha20Poly1305Cipher<XChaCha20Adapter>
	{
		private readonly XChaCha20Cipher _cipher;

		internal XChaCha20Adapter(XChaCha20Cipher cipher)
		{
			_cipher = cipher;
		}

		public static void SetCounter(XChaCha20Adapter cipher, uint counter)
		{
			cipher._cipher.SetCounter(counter);
		}

		public static void DerivePoly1305Key(XChaCha20Adapter cipher, Span<byte> destination)
		{
			cipher._cipher.DerivePoly1305Key(destination);
		}

		public static void Xor(XChaCha20Adapter cipher, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			cipher._cipher.Xor(source, destination);
		}
	}
}
