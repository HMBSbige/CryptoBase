using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos
{
	public class BcAESCrypto : BlockCryptoBase
	{
		public override string Name => @"AES";

		public override int BlockSize => 16;

		public sealed override bool IsEncrypt { get; init; }

		private readonly AesEngine _engine;
		private readonly byte[] _buffer = new byte[16];
		private readonly byte[] _outBuffer = new byte[16];

		public BcAESCrypto(bool isEncrypt, byte[] key)
		{
			IsEncrypt = isEncrypt;
			_engine = new AesEngine();
			_engine.Init(isEncrypt, new KeyParameter(key));
		}

		public override void UpdateBlock(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			source.Slice(0, BlockSize).CopyTo(_buffer);
			_engine.ProcessBlock(_buffer, 0, _outBuffer, 0);
			_outBuffer.CopyTo(destination);
		}

		public override void Reset()
		{

		}
	}
}
