using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes
{
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

		public override unsafe void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Encrypt(source, destination);

			fixed (byte* pSource = source)
			fixed (byte* pDestination = destination)
			fixed (byte* pBlock = _block)
			{
				IntrinsicsUtils.Xor(pBlock, pSource, pDestination, BlockSize);
			}

			InternalBlockCrypto.Encrypt(destination, destination);

			destination.Slice(0, BlockSize).CopyTo(_block);
		}

		public override unsafe void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Decrypt(source, destination);

			InternalBlockCrypto.Decrypt(source, destination);

			fixed (byte* pDestination = destination)
			fixed (byte* pBlock = _block)
			{
				IntrinsicsUtils.Xor(pBlock, pDestination, pDestination, BlockSize);
			}

			source.Slice(0, BlockSize).CopyTo(_block);
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
}
