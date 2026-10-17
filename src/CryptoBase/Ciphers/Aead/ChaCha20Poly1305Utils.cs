using CryptoBase.Ciphers.Streams;
using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Aead;

internal static class ChaCha20Poly1305Utils
{
	private const int KeyStreamBlockSize = 64;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void EncryptAndComputeTag(ChaCha20Cipher cipher, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(tag.Length == Poly1305Algorithm.MacLength);

		ref byte sourceStart = ref MemoryMarshal.GetReference(source);
		ref byte destinationStart = ref MemoryMarshal.GetReference(destination);
		ref byte tagStart = ref MemoryMarshal.GetReference(tag);
		ref byte associatedDataStart = ref MemoryMarshal.GetReference(associatedData);

		if (ChaCha20Utils.CanFusePoly1305<Poly1305Avx512>() && ExceedsFirstBatch(source.Length) || Poly1305Algorithm.ShouldUseAvx512(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			Encrypt<Poly1305Avx512>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
			return;
		}

		if (Poly1305Algorithm.ShouldUseAvx2(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			Encrypt<Poly1305Avx2>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
			return;
		}

		if (Poly1305Algorithm.ShouldUseSse2(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			Encrypt<Poly1305Sse2>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
			return;
		}

		if (Poly1305Algorithm.ShouldUseAdvSimd(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			Encrypt<Poly1305AdvSimd>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
			return;
		}

		Encrypt<Poly1305Software>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryDecrypt(ChaCha20Cipher cipher, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(tag.Length == Poly1305Algorithm.MacLength);

		ref byte sourceStart = ref MemoryMarshal.GetReference(source);
		ref byte destinationStart = ref MemoryMarshal.GetReference(destination);
		ref byte tagStart = ref MemoryMarshal.GetReference(tag);
		ref byte associatedDataStart = ref MemoryMarshal.GetReference(associatedData);

		if (ChaCha20Utils.CanFusePoly1305<Poly1305Avx512>() && ExceedsFirstBatch(source.Length) || Poly1305Algorithm.ShouldUseAvx512(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			return Decrypt<Poly1305Avx512>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
		}

		if (Poly1305Algorithm.ShouldUseAvx2(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			return Decrypt<Poly1305Avx2>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
		}

		if (Poly1305Algorithm.ShouldUseSse2(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			return Decrypt<Poly1305Sse2>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
		}

		if (Poly1305Algorithm.ShouldUseAdvSimd(associatedData.Length, source.Length, Poly1305Algorithm.BlockSizeInBytes))
		{
			return Decrypt<Poly1305AdvSimd>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
		}

		return Decrypt<Poly1305Software>(cipher, ref sourceStart, ref destinationStart, source.Length, ref tagStart, ref associatedDataStart, associatedData.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ExceedsFirstBatch(int length)
	{
		return length > ChaCha20Utils.BatchLength - KeyStreamBlockSize;
	}

	// Block 0 and the start of the message share the first keystream batch; a block-aligned message too long to fit puts only length % BatchLength there, so whole batches follow.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int GetPrefixLength(int length)
	{
		int prefixLength = ExceedsFirstBatch(length) && length % KeyStreamBlockSize is 0 ? length % ChaCha20Utils.BatchLength : Math.Min(length, ChaCha20Utils.BatchLength - KeyStreamBlockSize);
		Debug.Assert(prefixLength <= ChaCha20Utils.BatchLength - KeyStreamBlockSize);
		return prefixLength;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int GetFirstBatchLength(int prefixLength)
	{
		return prefixLength + 2 * KeyStreamBlockSize - 1 & -KeyStreamBlockSize;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Encrypt<TState>(ChaCha20Cipher cipher, ref byte sourceStart, ref byte destinationStart, int length, ref byte tagStart, ref byte associatedDataStart, int associatedDataLength) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);
		Span<byte> lengthBlock = stackalloc byte[Poly1305Algorithm.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock, (ulong)associatedDataLength);
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.Slice(8), (ulong)length);

		int prefixLength = GetPrefixLength(length);
		Span<byte> buffer = stackalloc byte[ChaCha20Utils.BatchLength];
		using CryptoBuffer<byte> firstBatch = new(buffer.Slice(0, GetFirstBatchLength(prefixLength)));
		DeriveKeyStream(cipher, firstBatch.Span);

		Unsafe.SkipInit(out TState state);
		TState.Initialize(ref state, firstBatch.Span.Slice(0, Poly1305Algorithm.KeyLengthInBytes));

		try
		{
			// Hash the associated data before writing the destination, which it may overlap.
			state.AppendPaddedSegment(associatedData);
			FastUtils.Xor(firstBatch.Span.Slice(KeyStreamBlockSize), source, destination, prefixLength);
			int hashed = 0;
			int processed = prefixLength;

			if (ChaCha20Utils.CanFusePoly1305<TState>() && processed < length)
			{
				processed = cipher.XorChunksAndAppendPoly1305(source, destination, ref state, processed, ref hashed, decrypt: false);
			}

			XorRemaining(cipher, source.Slice(processed), destination.Slice(processed));
			state.AppendPaddedSegment(destination.Slice(hashed));
			state.AppendPaddedSegment(lengthBlock);
			state.WriteMac(MemoryMarshal.CreateSpan(ref tagStart, Poly1305Algorithm.MacLength));
		}
		finally
		{
			state.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static bool Decrypt<TState>(ChaCha20Cipher cipher, ref byte sourceStart, ref byte destinationStart, int length, ref byte tagStart, ref byte associatedDataStart, int associatedDataLength) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);
		Span<byte> lengthBlock = stackalloc byte[Poly1305Algorithm.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock, (ulong)associatedDataLength);
		BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.Slice(8), (ulong)length);

		int prefixLength = GetPrefixLength(length);
		Span<byte> buffer = stackalloc byte[ChaCha20Utils.BatchLength];
		using CryptoBuffer<byte> firstBatch = new(buffer.Slice(0, GetFirstBatchLength(prefixLength)));
		DeriveKeyStream(cipher, firstBatch.Span);
		bool fused = ChaCha20Utils.CanFusePoly1305<TState>() && prefixLength < length;
		int processed = 0;
		int hashed = 0;
		Unsafe.SkipInit(out Vector128<byte> computedTag);

		Unsafe.SkipInit(out TState state);
		TState.Initialize(ref state, firstBatch.Span.Slice(0, Poly1305Algorithm.KeyLengthInBytes));

		try
		{
			state.AppendPaddedSegment(associatedData);

			// The fused kernel writes plaintext before the tag is known, so it hashes each chunk before storing over it.
			if (fused)
			{
				state.AppendMessage(source.Slice(0, prefixLength));
				FastUtils.Xor(firstBatch.Span.Slice(KeyStreamBlockSize), source, destination, prefixLength);
				hashed = prefixLength;
				processed = cipher.XorChunksAndAppendPoly1305(source, destination, ref state, prefixLength, ref hashed, decrypt: true);
				Debug.Assert(hashed == processed);
			}

			state.AppendPaddedSegment(source.Slice(hashed));
			state.AppendPaddedSegment(lengthBlock);
			state.WriteMac(computedTag.AsSpan());
		}
		finally
		{
			state.ZeroMemory();
		}

		if (!FixedTime.Equals16(computedTag.AsReadOnlySpan(), MemoryMarshal.CreateReadOnlySpan(ref tagStart, Poly1305Algorithm.MacLength)))
		{
			destination.ZeroMemory();
			return false;
		}

		if (!fused)
		{
			FastUtils.Xor(firstBatch.Span.Slice(KeyStreamBlockSize), source, destination, prefixLength);
			processed = prefixLength;
		}

		XorRemaining(cipher, source.Slice(processed), destination.Slice(processed));
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DeriveKeyStream(ChaCha20Cipher cipher, Span<byte> destination)
	{
		destination.Clear();
		cipher.XorWholeBlocks(destination, destination);
	}

	// Whole blocks go straight to the output, except that a final partial block shares one keystream batch with the whole blocks of its batch.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorRemaining(ChaCha20Cipher cipher, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int direct = source.Length % KeyStreamBlockSize is 0 ? source.Length : source.Length & -ChaCha20Utils.BatchLength;

		if (direct > 0)
		{
			cipher.XorWholeBlocks(source.Slice(0, direct), destination.Slice(0, direct));
		}

		if (direct < source.Length)
		{
			XorFromKeyStream(cipher, source.Slice(direct), destination.Slice(direct));
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void XorFromKeyStream(ChaCha20Cipher cipher, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Span<byte> buffer = stackalloc byte[ChaCha20Utils.BatchLength];
		using CryptoBuffer<byte> keyStream = new(buffer.Slice(0, source.Length + KeyStreamBlockSize - 1 & -KeyStreamBlockSize));
		DeriveKeyStream(cipher, keyStream.Span);
		FastUtils.Xor(keyStream.Span, source, destination, source.Length);
	}
}
