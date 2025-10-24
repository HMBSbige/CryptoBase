using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CBCBlockMode : BlockCryptoBase
{
	public override string Name => _internalBlockCrypto.Name + @"-CBC";

	public override int BlockSize => _internalBlockCrypto.BlockSize;

	private readonly IBlockCrypto _internalBlockCrypto;

	private readonly ReadOnlyMemory<byte> _iv;

	private readonly byte[] _block;

	public CBCBlockMode(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, crypto.BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;
		_iv = iv.ToArray();

		_block = ArrayPool<byte>.Shared.Rent(BlockSize);

		Reset();
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		FastUtils.Xor(_block, source, destination, BlockSize);

		_internalBlockCrypto.Encrypt(destination, destination);

		destination.Slice(0, BlockSize).CopyTo(_block);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		_internalBlockCrypto.Decrypt(source, destination);

		FastUtils.Xor(destination, _block, BlockSize);

		source.Slice(0, BlockSize).CopyTo(_block);
	}

	public override void Reset()
	{
		base.Reset();
		_internalBlockCrypto.Reset();

		_iv.Span.CopyTo(_block);
	}

	public override void Dispose()
	{
		base.Dispose();

		_internalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_block);
	}
}
