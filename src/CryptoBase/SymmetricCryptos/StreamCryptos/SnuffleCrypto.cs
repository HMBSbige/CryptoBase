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

	protected readonly uint[] State = ArrayPool<uint>.Shared.Rent(StateSize);
	protected readonly byte[] KeyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));

	protected int Index;

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Update(source, destination);

		int length = source.Length;
		int offset = 0;
		ReadOnlySpan<byte> keyStream = KeyStream;

		while (length > 0)
		{
			if (Index is 0)
			{
				int processed = UpdateBlocks(source.Slice(offset), destination.Slice(offset));
				length -= processed;
				offset += processed;

				if (length is 0)
				{
					break;
				}

				UpdateKeyStream();
				IncrementCounter();
			}

			int r = StateSize * sizeof(uint) - Index;
			FastUtils.Xor(keyStream.Slice(Index), source.Slice(offset), destination.Slice(offset), Math.Min(r, length));

			if (length < r)
			{
				Index += length;
				return;
			}

			Index = 0;
			length -= r;
			offset += r;
		}
	}

	protected abstract int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination);
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
