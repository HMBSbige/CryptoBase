using CryptoBase.Macs.Poly1305;
using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.SymmetricCryptos.AeadCryptos;

internal static class ChaCha20Poly1305Utils
{
	[SkipLocalsInit]
	internal static void EncryptAndComputeTag(ChaCha20Crypto chacha20, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		EncryptAndComputeTag(new ChaCha20Cipher(chacha20), source, destination, tag, associatedData);
	}

	[SkipLocalsInit]
	internal static void EncryptAndComputeTag(XChaCha20Crypto chacha20, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		EncryptAndComputeTag(new XChaCha20Cipher(chacha20), source, destination, tag, associatedData);
	}

	[SkipLocalsInit]
	private static void EncryptAndComputeTag<TCipher>(TCipher cipher, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData) where TCipher : struct, IChaCha20Poly1305Cipher<TCipher>
	{
		Debug.Assert(tag.Length == Poly1305Algorithm.MacLengthInBytes);

		using CryptoBuffer<byte> poly1305Key = new(stackalloc byte[Poly1305Algorithm.KeyLengthInBytes]);
		Span<byte> lengthBlock = stackalloc byte[Poly1305Algorithm.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.Slice(8), (ulong)source.Length);

		TCipher.SetCounter(cipher, 0);
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
			TCipher.Update(cipher, source, destination);
			state.AppendPaddedSegment(destination);
			state.AppendPaddedSegment(lengthBlock);
			state.WriteMac(tag);
		}
		finally
		{
			state.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	internal static void ComputeTag(ChaCha20Crypto chacha20, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
	{
		ComputeTag(new ChaCha20Cipher(chacha20), associatedData, ciphertext, tag);
	}

	[SkipLocalsInit]
	internal static void ComputeTag(XChaCha20Crypto chacha20, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
	{
		ComputeTag(new XChaCha20Cipher(chacha20), associatedData, ciphertext, tag);
	}

	[SkipLocalsInit]
	private static void ComputeTag<TCipher>(TCipher cipher, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> tag) where TCipher : struct, IChaCha20Poly1305Cipher<TCipher>
	{
		Debug.Assert(tag.Length == Poly1305Algorithm.MacLengthInBytes);

		using CryptoBuffer<byte> poly1305Key = new(stackalloc byte[Poly1305Algorithm.KeyLengthInBytes]);
		TCipher.DerivePoly1305Key(cipher, poly1305Key.Span);

		Span<byte> lengthBlock = stackalloc byte[Poly1305Algorithm.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.Slice(8), (ulong)ciphertext.Length);
		Poly1305Algorithm.MacPaddedSegments(poly1305Key.Span, associatedData, ciphertext, lengthBlock, tag);
	}

	private interface IChaCha20Poly1305Cipher<TSelf> where TSelf : struct, IChaCha20Poly1305Cipher<TSelf>
	{
		static abstract void SetCounter(TSelf cipher, uint counter);

		static abstract void DerivePoly1305Key(TSelf cipher, Span<byte> destination);

		static abstract void Update(TSelf cipher, ReadOnlySpan<byte> source, Span<byte> destination);
	}

	private readonly struct ChaCha20Cipher : IChaCha20Poly1305Cipher<ChaCha20Cipher>
	{
		private readonly ChaCha20Crypto _cipher;

		internal ChaCha20Cipher(ChaCha20Crypto cipher)
		{
			_cipher = cipher;
		}

		public static void SetCounter(ChaCha20Cipher cipher, uint counter)
		{
			cipher._cipher.SetCounter(counter);
		}

		public static void DerivePoly1305Key(ChaCha20Cipher cipher, Span<byte> destination)
		{
			cipher._cipher.DerivePoly1305Key(destination);
		}

		public static void Update(ChaCha20Cipher cipher, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			cipher._cipher.Update(source, destination);
		}
	}

	private readonly struct XChaCha20Cipher : IChaCha20Poly1305Cipher<XChaCha20Cipher>
	{
		private readonly XChaCha20Crypto _cipher;

		internal XChaCha20Cipher(XChaCha20Crypto cipher)
		{
			_cipher = cipher;
		}

		public static void SetCounter(XChaCha20Cipher cipher, uint counter)
		{
			cipher._cipher.SetCounter(counter);
		}

		public static void DerivePoly1305Key(XChaCha20Cipher cipher, Span<byte> destination)
		{
			cipher._cipher.DerivePoly1305Key(destination);
		}

		public static void Update(XChaCha20Cipher cipher, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			cipher._cipher.Update(source, destination);
		}
	}
}
