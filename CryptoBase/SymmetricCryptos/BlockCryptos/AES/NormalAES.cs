using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public sealed class NormalAES : AESCrypto
	{
		public override bool IsSupport => false;

		private readonly static Aes Aes;

		static NormalAES()
		{
			Aes = Aes.Create();
			Aes.Mode = CipherMode.ECB;
			Aes.Padding = PaddingMode.None;
		}

		private readonly ICryptoTransform _encryptor;
		private readonly ICryptoTransform _decryptor;

		private readonly byte[] _buffer;
		private readonly byte[] _outBuffer;

		public NormalAES(byte[] key) : base(key)
		{
			_encryptor = Aes.CreateEncryptor(key, null);
			_decryptor = Aes.CreateDecryptor(key, null);

			_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
			_outBuffer = ArrayPool<byte>.Shared.Rent(BlockSize);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Encrypt(source, destination);

			source.Slice(0, BlockSize).CopyTo(_buffer);
			_encryptor.TransformBlock(_buffer, 0, BlockSize, _outBuffer, 0);
			_outBuffer.CopyTo(destination);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Decrypt(source, destination);

			source.Slice(0, BlockSize).CopyTo(_buffer);
			_decryptor.TransformBlock(_buffer, 0, BlockSize, _outBuffer, 0);
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
