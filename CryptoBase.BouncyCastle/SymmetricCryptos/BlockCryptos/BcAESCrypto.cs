using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos
{
	public class BcAESCrypto : BlockCryptoBase
	{
		public override string Name => @"AES";

		public sealed override int BlockSize => 16;

		public sealed override bool IsEncrypt { get; init; }

		private readonly AesEngine _engine;
		private readonly byte[] _buffer;
		private readonly byte[] _outBuffer;

		public BcAESCrypto(bool isEncrypt, byte[] key)
		{
			IsEncrypt = isEncrypt;

			_engine = new AesEngine();
			_engine.Init(isEncrypt, new KeyParameter(key));

			_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
			_outBuffer = ArrayPool<byte>.Shared.Rent(BlockSize);
		}

		public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			source.Slice(0, BlockSize).CopyTo(_buffer);
			_engine.ProcessBlock(_buffer, 0, _outBuffer, 0);
			_outBuffer.CopyTo(destination);
		}

		public override void Reset() { }

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<byte>.Shared.Return(_buffer);
			ArrayPool<byte>.Shared.Return(_outBuffer);
		}
	}
}
