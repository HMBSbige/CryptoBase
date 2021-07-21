using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos
{
	public class BcSM4Crypto : BlockCryptoBase
	{
		public override string Name => @"SM4";

		public sealed override int BlockSize => 16;

		private bool _isEncrypt;

		private readonly IBlockCipher _engine;
		private readonly KeyParameter _key;
		private readonly byte[] _buffer;
		private readonly byte[] _outBuffer;

		public BcSM4Crypto(bool isEncrypt, byte[] key)
		{
			_engine = new SM4Engine();
			_key = new KeyParameter(key);

			_isEncrypt = isEncrypt;
			_engine.Init(_isEncrypt, _key);

			_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
			_outBuffer = ArrayPool<byte>.Shared.Rent(BlockSize);
		}

		public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Encrypt(source, destination);
			if (!_isEncrypt)
			{
				_engine.Init(true, _key);
				_isEncrypt = true;
			}

			Update(source, destination);
		}

		public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Decrypt(source, destination);
			if (_isEncrypt)
			{
				_engine.Init(false, _key);
				_isEncrypt = false;
			}

			Update(source, destination);
		}

		private void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			source[..BlockSize].CopyTo(_buffer);
			_engine.ProcessBlock(_buffer, 0, _outBuffer, 0);
			_outBuffer.CopyTo(destination);
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<byte>.Shared.Return(_buffer);
			ArrayPool<byte>.Shared.Return(_outBuffer);
		}
	}
}
