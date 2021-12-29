using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using System;
using System.Buffers;

namespace CryptoBase.BouncyCastle.Digests;

public abstract class BcDigest : IHash
{
	public abstract string Name { get; }
	public abstract int Length { get; }
	public abstract int BlockSize { get; }

	private readonly IDigest _hasher;

	protected BcDigest(IDigest hasher)
	{
		_hasher = hasher;
	}

	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		var buffer = ArrayPool<byte>.Shared.Rent(source.Length);
		try
		{
			source.CopyTo(buffer);
			_hasher.BlockUpdate(buffer, 0, source.Length);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	public void GetHash(Span<byte> destination)
	{
		var outBuffer = ArrayPool<byte>.Shared.Rent(Length);
		try
		{
			_hasher.DoFinal(outBuffer, 0);
			outBuffer.AsSpan(0, Length).CopyTo(destination);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(outBuffer);
		}
	}

	public void Reset()
	{
		_hasher.Reset();
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
