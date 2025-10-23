using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CBCBlockMode : BlockCryptoBase, IBlockCryptoMode
{
	public override string Name => InternalBlockCrypto.Name + @"-CBC";

	public override int BlockSize => InternalBlockCrypto.BlockSize;

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly byte[] _block;

	public CBCBlockMode(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, crypto.BlockSize, nameof(iv));

		InternalBlockCrypto = crypto;
		Iv = iv.ToArray();

		_block = ArrayPool<byte>.Shared.Rent(BlockSize);

		Reset();
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		FastUtils.Xor(_block, source, destination, BlockSize);

		InternalBlockCrypto.Encrypt(destination, destination);

		destination.Slice(0, BlockSize).CopyTo(_block);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		InternalBlockCrypto.Decrypt(source, destination);

		FastUtils.Xor(destination, _block, BlockSize);

		source.Slice(0, BlockSize).CopyTo(_block);
	}

	public override void Reset()
	{
		base.Reset();
		InternalBlockCrypto.Reset();

		Iv.Span.CopyTo(_block);
	}

	public override void Dispose()
	{
		base.Dispose();

		InternalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_block);
	}
}
