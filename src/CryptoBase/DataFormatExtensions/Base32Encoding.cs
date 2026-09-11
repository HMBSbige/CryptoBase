using System.Buffers;
using System.Numerics;

namespace CryptoBase.DataFormatExtensions;

/// <summary>
/// Represents a Base32 encoder and decoder configured with a 32-character ASCII alphabet.
/// </summary>
public sealed partial class Base32Encoding
{
	private const int AlphabetLength = 32;
	private const int InputBytesPerBlock = 5;
	private const int OutputSymbolsPerBlock = 8;
	private const int SymbolMask = 31;
	private const byte InvalidSymbol = byte.MaxValue;
	private const char DefaultPadding = '=';
	private const string Rfc4648Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	private const string Rfc4648HexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

	private readonly byte[] _alphabet;
	private readonly byte[] _decodeTable;
	private readonly byte _padding;
	private readonly bool _omitPadding;
	private readonly byte _alphabetKind;

	/// <summary>
	/// Gets the padded RFC 4648 Base32 encoding.
	/// </summary>
	public static Base32Encoding Rfc4648 { get; } = new(Rfc4648Alphabet, DefaultPadding);

	/// <summary>
	/// Gets the padded RFC 4648 Base32hex encoding.
	/// </summary>
	public static Base32Encoding Rfc4648Hex { get; } = new(Rfc4648HexAlphabet, DefaultPadding);

	private Base32Encoding(string alphabet, char padding)
	{
		if (alphabet.Length is not AlphabetLength)
		{
			throw new ArgumentException("The alphabet must contain exactly 32 characters.", nameof(alphabet));
		}

		if (padding is '\0' or > '\u007f')
		{
			throw new ArgumentException("The padding character must be an ASCII character.", nameof(padding));
		}

		_padding = (byte)padding;
		(_alphabet, _decodeTable) = CreateTables(alphabet, _padding);
		_omitPadding = false;
		_alphabetKind = alphabet switch
		{
			Rfc4648Alphabet => Rfc4648AlphabetKind,
			Rfc4648HexAlphabet => Rfc4648HexAlphabetKind,
			_ => CustomAlphabetKind
		};
		OmitPadding = new Base32Encoding(_alphabet, _padding, _decodeTable, _alphabetKind);
	}

	private Base32Encoding(byte[] alphabet, byte padding, byte[] decodeTable, byte alphabetKind)
	{
		_alphabet = alphabet;
		_padding = padding;
		_omitPadding = true;
		_decodeTable = decodeTable;
		_alphabetKind = alphabetKind;
		OmitPadding = this;
	}

	/// <summary>
	/// Gets an encoding that uses the same alphabet, omits padding when encoding, and rejects padded input when decoding.
	/// </summary>
	public Base32Encoding OmitPadding { get; }

	/// <summary>
	/// Creates a padded Base32 encoding that uses a custom ASCII alphabet.
	/// </summary>
	/// <param name="alphabet">The 32 distinct ASCII characters used as encoding symbols. The alphabet must not contain <paramref name="padding" />.</param>
	/// <param name="padding">The non-NUL ASCII character used for padding.</param>
	/// <returns>A padded Base32 encoding configured with the specified alphabet and padding character.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="alphabet" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="alphabet" /> is not exactly 32 characters long, contains non-ASCII or duplicate characters, or contains <paramref name="padding" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="padding" /> is the NUL character or is not an ASCII character.</exception>
	public static Base32Encoding Create(string alphabet, char padding = DefaultPadding)
	{
		ArgumentNullException.ThrowIfNull(alphabet);
		return new Base32Encoding(alphabet, padding);
	}

	/// <summary>
	/// Gets the exact number of output symbols required to encode a source of the specified byte length.
	/// </summary>
	/// <param name="sourceLength">The number of source bytes.</param>
	/// <returns>The required number of destination characters or UTF-8 bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="sourceLength" /> is negative or produces an encoded length greater than <see cref="int.MaxValue" />.</exception>
	public int GetEncodedLength(int sourceLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(sourceLength);

		(int blockCount, int remainder) = Math.DivRem(sourceLength, InputBytesPerBlock);
		long encodedLength = (long)blockCount * OutputSymbolsPerBlock;

		if (remainder is not 0)
		{
			encodedLength += _omitPadding ? GetUnpaddedEncodedLength(remainder) : OutputSymbolsPerBlock;
		}

		if (encodedLength > int.MaxValue)
		{
			throw new ArgumentOutOfRangeException(nameof(sourceLength));
		}

		return (int)encodedLength;
	}

	/// <summary>
	/// Gets the maximum number of bytes that can be decoded from the specified number of Base32 symbols.
	/// </summary>
	/// <param name="encodedLength">The number of encoded symbols, including any padding.</param>
	/// <returns>The maximum number of decoded bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="encodedLength" /> is negative.</exception>
	public static int GetMaxDecodedLength(int encodedLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(encodedLength);

		return (int)((long)encodedLength * InputBytesPerBlock / OutputSymbolsPerBlock);
	}

	/// <summary>
	/// Encodes bytes as Base32 characters.
	/// </summary>
	/// <param name="source">The input span which contains binary data that needs to be encoded.</param>
	/// <param name="destination">The output span which contains the result of the operation, i.e. the ASCII chars in Base32.</param>
	/// <param name="bytesConsumed">When this method returns, contains the number of input bytes consumed during the operation. This can be used to slice the input for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="charsWritten">When this method returns, contains the number of chars written into the output span. This can be used to slice the output for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="isFinalBlock"><see langword="true" /> when the input span contains the entirety of data to encode; <see langword="false" /> when more data may follow,
	/// such as when calling in a loop. Calls with <see langword="false" /> should be followed up with another call where this parameter is <see langword="true" />. The default is <see langword="true" />.</param>
	/// <returns>The encoding status: <see cref="OperationStatus.Done" />, <see cref="OperationStatus.DestinationTooSmall" />, or <see cref="OperationStatus.NeedMoreData" />.</returns>
	public OperationStatus EncodeToChars(ReadOnlySpan<byte> source, Span<char> destination, out int bytesConsumed, out int charsWritten, bool isFinalBlock = true)
	{
		return EncodeCore(source, destination, out bytesConsumed, out charsWritten, isFinalBlock, Base32SimdPath.Auto);
	}

	internal OperationStatus EncodeToCharsPath(ReadOnlySpan<byte> source, Span<char> destination, out int bytesConsumed, out int charsWritten, bool isFinalBlock, Base32SimdPath path)
	{
		return EncodeCore(source, destination, out bytesConsumed, out charsWritten, isFinalBlock, path);
	}

	/// <summary>
	/// Encodes bytes as Base32 text represented by UTF-8 bytes.
	/// </summary>
	/// <param name="source">The input span which contains binary data that needs to be encoded.</param>
	/// <param name="destination">The output span which contains the result of the operation, i.e. the UTF-8 encoded text in Base32.</param>
	/// <param name="bytesConsumed">When this method returns, contains the number of input bytes consumed during the operation. This can be used to slice the input for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="bytesWritten">When this method returns, contains the number of bytes written into the output span. This can be used to slice the output for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="isFinalBlock"><see langword="true" /> when the input span contains the entirety of data to encode; <see langword="false" /> when more data may follow,
	/// such as when calling in a loop. Calls with <see langword="false" /> should be followed up with another call where this parameter is <see langword="true" />. The default is <see langword="true" />.</param>
	/// <returns>The encoding status: <see cref="OperationStatus.Done" />, <see cref="OperationStatus.DestinationTooSmall" />, or <see cref="OperationStatus.NeedMoreData" />.</returns>
	public OperationStatus EncodeToUtf8(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesConsumed, out int bytesWritten, bool isFinalBlock = true)
	{
		return EncodeCore(source, destination, out bytesConsumed, out bytesWritten, isFinalBlock, Base32SimdPath.Auto);
	}

	internal OperationStatus EncodeToUtf8Path(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesConsumed, out int bytesWritten, bool isFinalBlock, Base32SimdPath path)
	{
		return EncodeCore(source, destination, out bytesConsumed, out bytesWritten, isFinalBlock, path);
	}

	private OperationStatus EncodeCore<T>(ReadOnlySpan<byte> source, Span<T> destination, out int bytesConsumed, out int symbolsWritten, bool isFinalBlock, Base32SimdPath path) where T : unmanaged, INumberBase<T>
	{
		bytesConsumed = 0;
		symbolsWritten = 0;

		bool complete = typeof(T) == typeof(char)
			? TryEncodeCharsBlocks(source, MemoryMarshal.Cast<T, char>(destination), out int sourceOffset, out int destinationOffset, path)
			: TryEncodeUtf8Blocks(source, MemoryMarshal.Cast<T, byte>(destination), out sourceOffset, out destinationOffset, path);

		if (!complete)
		{
			bytesConsumed = sourceOffset;
			symbolsWritten = destinationOffset;
			return OperationStatus.DestinationTooSmall;
		}

		int remaining = source.Length - sourceOffset;

		if (remaining is 0)
		{
			bytesConsumed = sourceOffset;
			symbolsWritten = destinationOffset;
			return OperationStatus.Done;
		}

		if (!isFinalBlock)
		{
			bytesConsumed = sourceOffset;
			symbolsWritten = destinationOffset;
			return OperationStatus.NeedMoreData;
		}

		int symbolCount = GetUnpaddedEncodedLength(remaining);
		int finalLength = _omitPadding ? symbolCount : OutputSymbolsPerBlock;

		if (destination.Length - destinationOffset < finalLength)
		{
			bytesConsumed = sourceOffset;
			symbolsWritten = destinationOffset;
			return OperationStatus.DestinationTooSmall;
		}

		EncodeTail(source.Slice(sourceOffset, remaining), destination.Slice(destinationOffset));

		if (!_omitPadding)
		{
			destination.Slice(destinationOffset + symbolCount, finalLength - symbolCount).Fill(T.CreateChecked(_padding));
		}

		destinationOffset += finalLength;

		bytesConsumed = source.Length;
		symbolsWritten = destinationOffset;
		return OperationStatus.Done;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryEncodeCharsBlocks(ReadOnlySpan<byte> source, Span<char> destination, out int sourceOffset, out int destinationOffset, Base32SimdPath path)
	{
		sourceOffset = 0;
		destinationOffset = 0;

		if (path is not Base32SimdPath.Auto)
		{
			int simdConsumed = EncodeCharsForced(source, destination, _alphabetKind, path);
			sourceOffset += simdConsumed;
			destinationOffset += simdConsumed / InputBytesPerBlock * OutputSymbolsPerBlock;
		}
		else if (source.Length >= X86EncodeCharsSimdThreshold && destination.Length >= 16 && _alphabetKind is not CustomAlphabetKind)
		{
			int simdConsumed = AdvSimd.IsSupported
				? EncodeCharsAdvSimdAuto(source, destination, sourceOffset, destinationOffset, _alphabetKind)
				: EncodeCharsAuto(source, destination, _alphabetKind);
			sourceOffset += simdConsumed;
			destinationOffset += simdConsumed / InputBytesPerBlock * OutputSymbolsPerBlock;
		}
		else if
		(
			source.Length >= X86EncodeVbmiVl128Threshold
			&& destination.Length >= 16
			&& _alphabetKind is not CustomAlphabetKind
			&& IsAvx512VbmiVlSupported()
		)
		{
			sourceOffset = EncodeCharsAvx512VbmiVl128Single(source, destination, _alphabetKind);
			destinationOffset = 16;
		}
		else if
		(
			_alphabetKind is CustomAlphabetKind
			&& source.Length >= X86EncodeVector256Threshold && destination.Length >= 32
			&& (IsAvx512VbmiVlSupported() || IsAvx512VbmiSupported())
		)
		{
			int simdConsumed = EncodeCharsCustomAuto(source, destination);
			sourceOffset += simdConsumed;
			destinationOffset += simdConsumed / InputBytesPerBlock * OutputSymbolsPerBlock;
		}
		else if
		(
			source.Length >= X86EncodeVbmiVl128Threshold
			&& destination.Length >= 16
			&& _alphabetKind is CustomAlphabetKind
			&& IsAvx512VbmiVlSupported()
		)
		{
			sourceOffset = EncodeCharsAvx512VbmiVl128CustomSingle(source, destination, _alphabet);
			destinationOffset = 16;
		}

		int availableBlocks = (source.Length - sourceOffset) / InputBytesPerBlock;
		int writableBlocks = (destination.Length - destinationOffset) / OutputSymbolsPerBlock;
		int blockCount = Math.Min(availableBlocks, writableBlocks);
		ref byte sourceReference = ref Unsafe.Add(ref source.GetReference(), sourceOffset);
		ref char destinationReference = ref Unsafe.Add(ref destination.GetReference(), destinationOffset);
		ref byte alphabetReference = ref MemoryMarshal.GetArrayDataReference(_alphabet);

		for (int block = 0; block < blockCount; ++block)
		{
			EncodeBlock(ref sourceReference, ref destinationReference, ref alphabetReference);
			sourceReference = ref Unsafe.Add(ref sourceReference, InputBytesPerBlock);
			destinationReference = ref Unsafe.Add(ref destinationReference, OutputSymbolsPerBlock);
		}

		sourceOffset += blockCount * InputBytesPerBlock;
		destinationOffset += blockCount * OutputSymbolsPerBlock;

		return blockCount >= availableBlocks;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryEncodeUtf8Blocks(ReadOnlySpan<byte> source, Span<byte> destination, out int sourceOffset, out int destinationOffset, Base32SimdPath path)
	{
		sourceOffset = 0;
		destinationOffset = 0;
		int simdConsumed = 0;

		if (path is not Base32SimdPath.Auto)
		{
			simdConsumed = EncodeUtf8Forced(source, destination, _alphabetKind, path);
		}
		else if (AdvSimd.IsSupported)
		{
			simdConsumed = EncodeUtf8Auto(source, destination, sourceOffset, destinationOffset, _alphabetKind);
		}
		else if
		(
			_alphabetKind is not CustomAlphabetKind
			&& destination.Length >= 16
			&& source.Length >= X86EncodeVbmiVl128Threshold
		)
		{
			simdConsumed = EncodeUtf8X86Auto(source, destination, _alphabetKind);
		}
		else if
		(
			_alphabetKind is CustomAlphabetKind
			&& source.Length >= X86EncodeVector256Threshold && destination.Length >= 32
			&& (IsAvx512VbmiVlSupported() || IsAvx512VbmiSupported())
		)
		{
			simdConsumed = EncodeUtf8CustomAuto(source, destination);
		}
		else if
		(
			_alphabetKind is CustomAlphabetKind
			&& source.Length >= X86EncodeVbmiVl128Threshold
			&& destination.Length >= 16
			&& IsAvx512VbmiVlSupported()
		)
		{
			simdConsumed = EncodeUtf8Avx512VbmiVl128CustomSingle(source, destination, _alphabet);
		}

		sourceOffset += simdConsumed;
		destinationOffset += simdConsumed / InputBytesPerBlock * OutputSymbolsPerBlock;
		int availableBlocks = (source.Length - sourceOffset) / InputBytesPerBlock;
		int writableBlocks = (destination.Length - destinationOffset) / OutputSymbolsPerBlock;
		int blockCount = Math.Min(availableBlocks, writableBlocks);
		ref byte sourceReference = ref Unsafe.Add(ref source.GetReference(), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref destination.GetReference(), destinationOffset);
		ref byte alphabetReference = ref MemoryMarshal.GetArrayDataReference(_alphabet);
		int sourceRemaining = source.Length - sourceOffset;
		int octCount = blockCount >> 3;

		if (octCount is not 0 && sourceRemaining - octCount * 40 < Pack5FastOverReadBytes)
		{
			--octCount;
		}

		for (int i = 0; i < octCount; ++i)
		{
			ulong value0 = Pack5Fast(ref sourceReference);
			ulong value1 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 5));
			ulong value2 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 10));
			ulong value3 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 15));
			ulong value4 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 20));
			ulong value5 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 25));
			ulong value6 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 30));
			ulong value7 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 35));
			EncodePackedBlock(value0, ref destinationReference, ref alphabetReference);
			EncodePackedBlock(value1, ref Unsafe.Add(ref destinationReference, 8), ref alphabetReference);
			EncodePackedBlock(value2, ref Unsafe.Add(ref destinationReference, 16), ref alphabetReference);
			EncodePackedBlock(value3, ref Unsafe.Add(ref destinationReference, 24), ref alphabetReference);
			EncodePackedBlock(value4, ref Unsafe.Add(ref destinationReference, 32), ref alphabetReference);
			EncodePackedBlock(value5, ref Unsafe.Add(ref destinationReference, 40), ref alphabetReference);
			EncodePackedBlock(value6, ref Unsafe.Add(ref destinationReference, 48), ref alphabetReference);
			EncodePackedBlock(value7, ref Unsafe.Add(ref destinationReference, 56), ref alphabetReference);
			sourceReference = ref Unsafe.Add(ref sourceReference, 40);
			destinationReference = ref Unsafe.Add(ref destinationReference, 64);
		}

		for (int i = octCount << 3; i < blockCount; ++i)
		{
			EncodeBlock(ref sourceReference, ref destinationReference, ref alphabetReference);
			sourceReference = ref Unsafe.Add(ref sourceReference, InputBytesPerBlock);
			destinationReference = ref Unsafe.Add(ref destinationReference, OutputSymbolsPerBlock);
		}

		sourceOffset += blockCount * InputBytesPerBlock;
		destinationOffset += blockCount * OutputSymbolsPerBlock;

		return blockCount >= availableBlocks;
	}

	/// <summary>
	/// Decodes Base32 characters into bytes.
	/// </summary>
	/// <param name="source">The input span which contains Unicode ASCII chars in Base32 that need to be decoded.</param>
	/// <param name="destination">The output span which contains the result of the operation, i.e. the decoded binary data.</param>
	/// <param name="charsConsumed">When this method returns, contains the number of input chars consumed during the operation. This can be used to slice the input for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="bytesWritten">When this method returns, contains the number of bytes written into the output span. This can be used to slice the output for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="isFinalBlock"><see langword="true" /> when the input span contains the entirety of data to decode; <see langword="false" /> when more data may follow,
	/// such as when calling in a loop. Calls with <see langword="false" /> should be followed up with another call where this parameter is <see langword="true" />. The default is <see langword="true" />.</param>
	/// <returns>The decoding status: <see cref="OperationStatus.Done" />, <see cref="OperationStatus.DestinationTooSmall" />, <see cref="OperationStatus.NeedMoreData" />, or <see cref="OperationStatus.InvalidData" />.</returns>
	public OperationStatus DecodeFromChars(ReadOnlySpan<char> source, Span<byte> destination, out int charsConsumed, out int bytesWritten, bool isFinalBlock = true)
	{
		return DecodeCore(source, destination, out charsConsumed, out bytesWritten, isFinalBlock, Base32SimdPath.Auto);
	}

	internal OperationStatus DecodeFromCharsPath(ReadOnlySpan<char> source, Span<byte> destination, out int charsConsumed, out int bytesWritten, bool isFinalBlock, Base32SimdPath path)
	{
		return DecodeCore(source, destination, out charsConsumed, out bytesWritten, isFinalBlock, path);
	}

	/// <summary>
	/// Decodes Base32 text represented by UTF-8 bytes.
	/// </summary>
	/// <param name="source">The input span which contains UTF-8 encoded text in Base32 that needs to be decoded.</param>
	/// <param name="destination">The output span which contains the result of the operation, i.e. the decoded binary data.</param>
	/// <param name="bytesConsumed">When this method returns, contains the number of input bytes consumed during the operation. This can be used to slice the input for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="bytesWritten">When this method returns, contains the number of bytes written into the output span. This can be used to slice the output for subsequent calls, if necessary. This parameter is treated as uninitialized.</param>
	/// <param name="isFinalBlock"><see langword="true" /> when the input span contains the entirety of data to decode; <see langword="false" /> when more data may follow,
	/// such as when calling in a loop. Calls with <see langword="false" /> should be followed up with another call where this parameter is <see langword="true" />. The default is <see langword="true" />.</param>
	/// <returns>The decoding status: <see cref="OperationStatus.Done" />, <see cref="OperationStatus.DestinationTooSmall" />, <see cref="OperationStatus.NeedMoreData" />, or <see cref="OperationStatus.InvalidData" />.</returns>
	public OperationStatus DecodeFromUtf8(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesConsumed, out int bytesWritten, bool isFinalBlock = true)
	{
		return DecodeCore(source, destination, out bytesConsumed, out bytesWritten, isFinalBlock, Base32SimdPath.Auto);
	}

	internal OperationStatus DecodeFromUtf8Path(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesConsumed, out int bytesWritten, bool isFinalBlock, Base32SimdPath path)
	{
		return DecodeCore(source, destination, out bytesConsumed, out bytesWritten, isFinalBlock, path);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private OperationStatus DecodeCore<T>(ReadOnlySpan<T> source, Span<byte> destination, out int symbolsConsumed, out int bytesWritten, bool isFinalBlock, Base32SimdPath path) where T : unmanaged, INumberBase<T>
	{
		if (!isFinalBlock)
		{
			return DecodeIncremental(source, destination, out symbolsConsumed, out bytesWritten, path);
		}

		if (!TryGetRawSymbolCount(source, out int symbolCount))
		{
			symbolsConsumed = 0;
			bytesWritten = 0;
			return OperationStatus.InvalidData;
		}

		return DecodeFinal(source, destination, symbolCount, out symbolsConsumed, out bytesWritten, path);
	}

	private OperationStatus DecodeFinal<T>(ReadOnlySpan<T> source, Span<byte> destination, int symbolCount, out int symbolsConsumed, out int bytesWritten, Base32SimdPath path) where T : unmanaged, INumberBase<T>
	{
		symbolsConsumed = 0;
		bytesWritten = 0;

		OperationStatus status = DecodeBlocks(source, destination, symbolCount & ~7, out int sourceOffset, out int destinationOffset, path);

		if (status is not OperationStatus.Done)
		{
			symbolsConsumed = sourceOffset;
			bytesWritten = destinationOffset;
			return status;
		}

		if (sourceOffset < symbolCount)
		{
			int tailSymbolCount = symbolCount - sourceOffset;

			if (destination.Length - destinationOffset < GetDecodedLength(tailSymbolCount))
			{
				symbolsConsumed = sourceOffset;
				bytesWritten = destinationOffset;
				return OperationStatus.DestinationTooSmall;
			}

			if (!HasCanonicalTrailingBits(source, symbolCount))
			{
				symbolsConsumed = sourceOffset;
				bytesWritten = destinationOffset;
				return OperationStatus.InvalidData;
			}

			ReadOnlySpan<T> tail = source.Slice(sourceOffset, tailSymbolCount);

			if (!TryDecodeTail(tail, destination.Slice(destinationOffset), out int tailConsumed, out int tailWritten))
			{
				symbolsConsumed = sourceOffset + tailConsumed;
				bytesWritten = destinationOffset + tailWritten;
				return OperationStatus.InvalidData;
			}

			destinationOffset += tailWritten;
		}

		symbolsConsumed = source.Length;
		bytesWritten = destinationOffset;
		return OperationStatus.Done;
	}

	private OperationStatus DecodeIncremental<T>(ReadOnlySpan<T> source, Span<byte> destination, out int symbolsConsumed, out int bytesWritten, Base32SimdPath path) where T : unmanaged, INumberBase<T>
	{
		symbolsConsumed = 0;
		bytesWritten = 0;

		OperationStatus status = DecodeBlocks(source, destination, source.Length & ~7, out int sourceOffset, out int destinationOffset, path);

		if (status is not OperationStatus.Done)
		{
			symbolsConsumed = sourceOffset;
			bytesWritten = destinationOffset;
			return status;
		}

		for (int i = sourceOffset; i < source.Length; ++i)
		{
			if (!TryGetValue(source[i], out _))
			{
				symbolsConsumed = i;
				bytesWritten = destinationOffset;
				return OperationStatus.InvalidData;
			}
		}

		symbolsConsumed = sourceOffset;
		bytesWritten = destinationOffset;
		return sourceOffset == source.Length ? OperationStatus.Done : OperationStatus.NeedMoreData;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private OperationStatus DecodeBlocks<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, out int symbolsConsumed, out int bytesWritten, Base32SimdPath path) where T : unmanaged
	{
		symbolsConsumed = 0;
		bytesWritten = 0;

		int sourceOffset = 0;
		int destinationOffset = 0;
		int simdConsumed = typeof(T) == typeof(char)
			? DecodeCharsBlocks(MemoryMarshal.Cast<T, char>(source), destination, fullLength, path)
			: DecodeUtf8Blocks(MemoryMarshal.Cast<T, byte>(source), destination, fullLength, path);
		sourceOffset += simdConsumed;
		destinationOffset += simdConsumed / OutputSymbolsPerBlock * InputBytesPerBlock;

		while (sourceOffset < fullLength)
		{
			if (destination.Length - destinationOffset < InputBytesPerBlock)
			{
				symbolsConsumed = sourceOffset;
				bytesWritten = destinationOffset;
				return OperationStatus.DestinationTooSmall;
			}

			if (!TryDecodeBlock(source, sourceOffset, destination, destinationOffset))
			{
				symbolsConsumed = sourceOffset;
				bytesWritten = destinationOffset;
				return OperationStatus.InvalidData;
			}

			sourceOffset += OutputSymbolsPerBlock;
			destinationOffset += InputBytesPerBlock;
		}

		symbolsConsumed = sourceOffset;
		bytesWritten = destinationOffset;
		return OperationStatus.Done;
	}

	private bool TryGetRawSymbolCount<T>(ReadOnlySpan<T> source, out int symbolCount) where T : unmanaged, INumberBase<T>
	{
		int unpaddedLength = source.TrimEnd(T.CreateChecked(_padding)).Length;

		return TryGetRawSymbolCount(source.Length, source.Length - unpaddedLength, out symbolCount);
	}

	private bool TryGetRawSymbolCount(int sourceLength, int paddingCount, out int symbolCount)
	{
		symbolCount = sourceLength - paddingCount;

		if (paddingCount is not 0)
		{
			if (_omitPadding || (sourceLength & 7) is not 0 || symbolCount is 0 || GetPaddingCount(symbolCount) != paddingCount)
			{
				symbolCount = 0;
				return false;
			}
		}
		else if (!_omitPadding && (sourceLength & 7) is not 0)
		{
			symbolCount = 0;
			return false;
		}

		if (!IsValidSymbolCount(symbolCount))
		{
			symbolCount = 0;
			return false;
		}

		return true;
	}

	private bool HasCanonicalTrailingBits<T>(ReadOnlySpan<T> source, int symbolCount) where T : unmanaged, INumberBase<T>
	{
		// Defer invalid-symbol detection to the block/tail scan so the consumed count reflects the valid prefix.
		return symbolCount is 0
				|| !TryGetValue(source[symbolCount - 1], out int value)
				|| (value & GetTrailingBitsMask(symbolCount)) is 0;
	}

	private static int GetUnpaddedEncodedLength(int sourceLength)
	{
		return (sourceLength * OutputSymbolsPerBlock + InputBytesPerBlock - 1) / InputBytesPerBlock;
	}

	private static int GetDecodedLength(int symbolCount)
	{
		return (int)((long)symbolCount * InputBytesPerBlock / OutputSymbolsPerBlock);
	}

	private static bool IsValidSymbolCount(int symbolCount)
	{
		return (symbolCount & 7) is 0 or 2 or 4 or 5 or 7;
	}

	private static int GetPaddingCount(int symbolCount)
	{
		return (symbolCount & 7) switch
		{
			0 => 0,
			2 => 6,
			4 => 4,
			5 => 3,
			7 => 1,
			_ => -1,
		};
	}

	private static int GetTrailingBitsMask(int symbolCount)
	{
		return (symbolCount & 7) switch
		{
			2 => 3,
			4 => 15,
			5 => 1,
			7 => 7,
			_ => 0,
		};
	}

	private static (byte[] Alphabet, byte[] DecodeTable) CreateTables(string alphabet, byte padding)
	{
		byte[] symbols = new byte[AlphabetLength];
		byte[] decodeTable = new byte[256];
		decodeTable.AsSpan().Fill(InvalidSymbol);

		for (int i = 0; i < alphabet.Length; ++i)
		{
			char symbol = alphabet[i];

			if (symbol > '\u007f')
			{
				throw new ArgumentException("The alphabet must contain ASCII characters.", nameof(alphabet));
			}

			byte value = (byte)symbol;

			if (value == padding || decodeTable[value] is not InvalidSymbol)
			{
				throw new ArgumentException("The alphabet characters must be distinct and cannot contain the padding character.", nameof(alphabet));
			}

			symbols[i] = value;
			decodeTable[value] = (byte)i;
		}

		return (symbols, decodeTable);
	}
}
