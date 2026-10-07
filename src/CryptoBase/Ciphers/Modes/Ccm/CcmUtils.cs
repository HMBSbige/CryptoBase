using CryptoBase.Ciphers.Modes.Ctr;

namespace CryptoBase.Ciphers.Modes.Ccm;

internal static class CcmUtils
{
	internal const int NonceSize = 12;
	private const int MaxMessageLength = (1 << 8 * LengthSize) - 1;

	private const int BlockSize = 16;
	private const int LengthSize = 15 - NonceSize;
	private const int CounterFlags = LengthSize - 1;
	private const int AssociatedDataFlag = 1 << 6;
	private const int ShortAssociatedDataLimit = 0xFF00;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ValidateInput<TTag>(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination, ReadOnlySpan<byte> tag) where TTag : struct, ICcmTag
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TTag.Size);

		if (source.Length > MaxMessageLength)
		{
			ThrowHelper.ThrowDataLimitExceeded(nameof(source));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Encrypt<TTag, TEncryptor>(TEncryptor encryptor, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData) where TTag : struct, ICcmTag where TEncryptor : ICcmBlockEncryptor, allows ref struct
	{
		Debug.Assert(nonce.Length is NonceSize && destination.Length == source.Length && tag.Length == TTag.Size);
		Encrypt<TTag, TEncryptor>(ref encryptor, ref nonce.GetReference(), ref source.GetReference(), ref destination.GetReference(), source.Length, ref tag.GetReference(), ref associatedData.GetReference(), associatedData.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryDecrypt<TTag, TEncryptor>(TEncryptor encryptor, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData) where TTag : struct, ICcmTag where TEncryptor : ICcmBlockEncryptor, allows ref struct
	{
		Debug.Assert(nonce.Length is NonceSize && destination.Length == source.Length && tag.Length == TTag.Size);
		return TryDecrypt<TTag, TEncryptor>(ref encryptor, ref nonce.GetReference(), ref source.GetReference(), ref tag.GetReference(), ref destination.GetReference(), source.Length, ref associatedData.GetReference(), associatedData.Length);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Encrypt<TTag, TEncryptor>(scoped ref TEncryptor encryptor, ref byte nonceStart, ref byte sourceStart, ref byte destinationStart, int length, ref byte tagStart, ref byte associatedDataStart, int associatedDataLength) where TTag : struct, ICcmTag where TEncryptor : ICcmBlockEncryptor, allows ref struct
	{
		ReadOnlySpan<byte> nonce = MemoryMarshal.CreateReadOnlySpan(ref nonceStart, NonceSize);
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		Span<byte> tag = MemoryMarshal.CreateSpan(ref tagStart, TTag.Size);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);

		Vector128<byte> counter = FormatBlocks<TTag>(nonce, source.Length, associatedData.Length, out Vector128<byte> state, out Vector128<byte> tagMask);
		encryptor.Begin(ref state, ref tagMask);
		AbsorbAssociatedData(ref encryptor, ref state, associatedData);

		if (!source.IsEmpty)
		{
			ref byte input = ref source.GetReference();
			ref byte output = ref destination.GetReference();
			nuint fullLength = (nuint)(source.Length & -BlockSize);

			for (nuint offset = 0; offset < fullLength; offset += BlockSize)
			{
				Vector128<byte> block = Vector128.LoadUnsafe(ref input, offset);
				Vector128<byte> keyStream = CtrLanes<CtrIncrementer32>.Next(ref counter);
				encryptor.Absorb(ref state, block, ref keyStream);
				(block ^ keyStream).StoreUnsafe(ref output, offset);
			}

			int finalLength = source.Length - (int)fullLength;

			if (finalLength is not 0)
			{
				Vector128<byte> finalBlock = Vector128.LoadPartialUnsafe(ref input, fullLength, finalLength);
				Vector128<byte> finalKeyStream = CtrLanes<CtrIncrementer32>.Next(ref counter);
				encryptor.Absorb(ref state, finalBlock, ref finalKeyStream);
				(finalBlock ^ finalKeyStream).StorePartialUnsafe(ref output, fullLength, finalLength);
			}
		}

		StoreTag<TTag>(encryptor.Finish(state) ^ tagMask, tag);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static bool TryDecrypt<TTag, TEncryptor>(scoped ref TEncryptor encryptor, ref byte nonceStart, ref byte sourceStart, ref byte tagStart, ref byte destinationStart, int length, ref byte associatedDataStart, int associatedDataLength) where TTag : struct, ICcmTag where TEncryptor : ICcmBlockEncryptor, allows ref struct
	{
		ReadOnlySpan<byte> nonce = MemoryMarshal.CreateReadOnlySpan(ref nonceStart, NonceSize);
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		ReadOnlySpan<byte> tag = MemoryMarshal.CreateReadOnlySpan(ref tagStart, TTag.Size);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);

		Vector128<byte> counter = FormatBlocks<TTag>(nonce, source.Length, associatedData.Length, out Vector128<byte> state, out Vector128<byte> tagMask);
		Vector128<byte> keyStream = source.IsEmpty ? tagMask : CtrLanes<CtrIncrementer32>.Next(ref counter);
		encryptor.Begin(ref state, ref keyStream);
		AbsorbAssociatedData(ref encryptor, ref state, associatedData);

		if (source.IsEmpty)
		{
			tagMask = keyStream;
		}
		else
		{
			ref byte input = ref source.GetReference();
			ref byte output = ref destination.GetReference();
			nuint finalOffset = (nuint)(source.Length - 1 & -BlockSize);

			for (nuint offset = 0; offset < finalOffset; offset += BlockSize)
			{
				Vector128<byte> block = Vector128.LoadUnsafe(ref input, offset) ^ keyStream;
				block.StoreUnsafe(ref output, offset);
				keyStream = CtrLanes<CtrIncrementer32>.Next(ref counter);
				encryptor.Absorb(ref state, block, ref keyStream);
			}

			int finalLength = source.Length - (int)finalOffset;
			Vector128<byte> finalBlock;

			if (finalLength is BlockSize)
			{
				finalBlock = Vector128.LoadUnsafe(ref input, finalOffset) ^ keyStream;
				finalBlock.StoreUnsafe(ref output, finalOffset);
			}
			else
			{
				finalBlock = Vector128.LoadPartialUnsafe(ref input, finalOffset, finalLength) ^ keyStream;
				finalBlock.StorePartialUnsafe(ref output, finalOffset, finalLength);

				// The MAC covers the zero-padded plaintext.
				finalBlock &= Vector128.LessThan(Vector128<sbyte>.Indices, Vector128.Create((sbyte)finalLength)).AsByte();
			}

			encryptor.Absorb(ref state, finalBlock, ref tagMask);
		}

		if (TagEquals<TTag>(encryptor.Finish(state) ^ tagMask, tag))
		{
			return true;
		}

		destination.ZeroMemory();
		return false;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> FormatBlocks<TTag>(ReadOnlySpan<byte> nonce, int messageLength, int associatedDataLength, out Vector128<byte> b0, out Vector128<byte> a0) where TTag : struct, ICcmTag
	{
		Debug.Assert(nonce.Length is NonceSize && (uint)messageLength <= MaxMessageLength);

		// Both blocks are flags || nonce || 3-byte big-endian value, read as little-endian halves.
		ref byte source = ref nonce.GetReference();
		ulong low = Unsafe.ReadUnaligned<ulong>(ref source) << 8;
		ulong high = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, NonceSize - sizeof(ulong))) >> 24;
		ulong length = (ulong)BinaryPrimitives.ReverseEndianness((uint)messageLength) << 32;
		int macFlags = (TTag.Size - 2) / 2 << 3 | CounterFlags | (associatedDataLength is 0 ? 0 : AssociatedDataFlag);

		b0 = Vector128.CreateUInt64(low | (uint)macFlags, high | length).AsByte();
		a0 = Vector128.CreateUInt64(low | CounterFlags, high).AsByte();
		return a0.ReverseEndianness128().IncUInt32LE();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AbsorbAssociatedData<TEncryptor>(scoped ref TEncryptor encryptor, ref Vector128<byte> state, scoped ReadOnlySpan<byte> associatedData) where TEncryptor : ICcmBlockEncryptor, allows ref struct
	{
		int length = associatedData.Length;

		if (length is 0)
		{
			return;
		}

		ref byte input = ref associatedData.GetReference();
		Vector128<byte> block;
		int offset;

		if (length < ShortAssociatedDataLimit)
		{
			offset = Math.Min(length, BlockSize - sizeof(ushort));
			block = PrefixLength(Vector128.LoadPartialUnsafe(ref input, 0, offset), BinaryPrimitives.ReverseEndianness((ushort)length), sizeof(ushort));
		}
		else
		{
			offset = BlockSize - sizeof(ushort) - sizeof(uint);
			block = PrefixLength(Vector128.LoadPartialUnsafe(ref input, 0, offset), 0xFEFF | (ulong)BinaryPrimitives.ReverseEndianness((uint)length) << 16, sizeof(ushort) + sizeof(uint));
		}

		while (true)
		{
			encryptor.Absorb(ref state, block);
			int remaining = length - offset;

			if (remaining <= 0)
			{
				return;
			}

			block = remaining < BlockSize ? Vector128.LoadPartialUnsafe(ref input, (nuint)offset, remaining) : Vector128.LoadUnsafe(ref input, (nuint)offset);
			offset += BlockSize;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> PrefixLength(Vector128<byte> data, ulong encodedLength, byte size)
	{
		return Vector128.Shuffle(data, Vector128<byte>.Indices - Vector128.Create(size)) | Vector128.CreateScalar(encodedLength).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreTag<TTag>(Vector128<byte> value, Span<byte> tag) where TTag : struct, ICcmTag
	{
		Debug.Assert(TTag.Size is 8 or 16 && tag.Length == TTag.Size);

		if (TTag.Size is 16)
		{
			value.StoreUnsafe(ref tag.GetReference());
		}
		else
		{
			Unsafe.WriteUnaligned(ref tag.GetReference(), value.AsUInt64().ToScalar());
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TagEquals<TTag>(Vector128<byte> expected, ReadOnlySpan<byte> tag) where TTag : struct, ICcmTag
	{
		Debug.Assert(TTag.Size is 8 or 16 && tag.Length == TTag.Size);
		ref byte actual = ref tag.GetReference();

		return TTag.Size is 16
			? FixedTime.Equals16(expected, Vector128.LoadUnsafe(ref actual))
			: (expected.AsUInt64().ToScalar() ^ Unsafe.ReadUnaligned<ulong>(ref actual)) is 0;
	}
}
