using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers.Binary;

namespace CryptoBase.Digests.CRC32;

public class Crc32SF : IHash
{
	public virtual string Name => @"CRC-32";

	public int Length => HashConstants.Crc32Length;

	public int BlockSize => HashConstants.Crc32BlockSize;

	protected virtual Crc32Table Table => Crc32Table.Crc32;

	private uint _state;

	public Crc32SF()
	{
		Reset();
	}

	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		_state = Table.Append(_state, source);
	}

	public void GetHash(Span<byte> destination)
	{
		BinaryPrimitives.WriteUInt32BigEndian(destination, _state);
		Reset();
	}

	public void Reset()
	{
		_state = uint.MinValue;
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
