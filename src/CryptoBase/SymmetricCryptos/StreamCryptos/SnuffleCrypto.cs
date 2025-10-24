using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public abstract class SnuffleCrypto : SnuffleCryptoBase
{
	/// <summary>
	/// expand 16-byte k
	/// </summary>
	protected static readonly uint[] Sigma16 = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

	/// <summary>
	/// expand 32-byte k
	/// </summary>
	protected static readonly uint[] Sigma32 = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

	protected byte Rounds { get; init; } = 20;

	protected readonly uint[] State;
	protected readonly byte[] KeyStream;

	protected int Index;

	protected SnuffleCrypto()
	{
		State = ArrayPool<uint>.Shared.Rent(StateSize);
		KeyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));
	}

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Update(source, destination);

		int length = source.Length;
		int sourceOffset = 0;
		int destOffset = 0;

		while (length > 0)
		{
			if (Index == 0)
			{
				UpdateBlocks(source[sourceOffset..], destination[destOffset..], ref length, ref sourceOffset, ref destOffset);

				if (length == 0)
				{
					break;
				}

				UpdateKeyStream();
				IncrementCounter();
			}

			int r = 64 - Index;
			int xorLen = Math.Min(r, length);
			IntrinsicsUtils.Xor(
				KeyStream.AsSpan(Index, xorLen),
				source.Slice(sourceOffset, xorLen),
				destination.Slice(destOffset, xorLen),
				xorLen);

			if (length < r)
			{
				Index += length;
				return;
			}

			Index = 0;
			length -= r;
			sourceOffset += r;
			destOffset += r;
		}
	}

	protected abstract void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset);
	protected abstract void UpdateKeyStream();
	protected abstract void IncrementCounter();

	public override void Dispose()
	{
		base.Dispose();

		ArrayPool<uint>.Shared.Return(State);
		ArrayPool<byte>.Shared.Return(KeyStream);

		GC.SuppressFinalize(this);
	}
}
