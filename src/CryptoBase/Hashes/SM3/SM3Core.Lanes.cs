namespace CryptoBase.Hashes.SM3;

public partial struct SM3Core
{
	// What the blocks SM3(m ‖ ct) share for the message m that this state has absorbed and 32-bit big-endian counters ct.
	[SkipLocalsInit]
	internal readonly void GetCounterBlocks(out SM3CounterBlocks blocks)
	{
		Unsafe.SkipInit(out blocks);
		int offset = (int)(_byteCount & BlockSizeInBytes - 1);
		blocks.Offset = offset;
		blocks.ChainingValue[0] = _v0;
		blocks.ChainingValue[1] = _v1;
		blocks.ChainingValue[2] = _v2;
		blocks.ChainingValue[3] = _v3;
		blocks.ChainingValue[4] = _v4;
		blocks.ChainingValue[5] = _v5;
		blocks.ChainingValue[6] = _v6;
		blocks.ChainingValue[7] = _v7;

		Unsafe.SkipInit(out InlineArray128<byte> padded);
		Span<byte> bytes = padded;
		ReadOnlySpan<byte> buffer = _buffer;
		buffer.Slice(0, offset).CopyTo(bytes);
		bytes.Slice(offset).Clear();
		bytes[offset + sizeof(uint)] = 0x80;
		int end = blocks.TwoBlocks ? 2 * BlockSizeInBytes : BlockSizeInBytes;
		BinaryPrimitives.WriteUInt64BigEndian(bytes.Slice(end - sizeof(ulong)), _byteCount + sizeof(uint) << 3);
		HashCoreUtils.LoadSixteenBigEndianWords(out blocks.Words[0], ref padded[0]);
		HashCoreUtils.LoadSixteenBigEndianWords(out blocks.Words[16], ref padded[BlockSizeInBytes]);
		bytes.ZeroMemory();
	}
}
