using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public class CBCBlockMode : BlockCryptoBase, IBlockCryptoMode
{
	public override string Name => InternalBlockCrypto.Name + @"-CBC";

	public sealed override int BlockSize => InternalBlockCrypto.BlockSize;

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly byte[] _block;

	public CBCBlockMode(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		if (iv.Length != crypto.BlockSize)
		{
			throw new ArgumentException(@"IV length must as the same as the block size.", nameof(iv));
		}

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

		destination[..BlockSize].CopyTo(_block);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		InternalBlockCrypto.Decrypt(source, destination);

		FastUtils.Xor(_block, destination, destination, BlockSize);

		source[..BlockSize].CopyTo(_block);
	}

	public sealed override void Reset()
	{
		base.Reset();
		InternalBlockCrypto.Reset();

		Iv.CopyTo(_block);
	}

	public override void Dispose()
	{
		base.Dispose();

		InternalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_block);
	}
}
