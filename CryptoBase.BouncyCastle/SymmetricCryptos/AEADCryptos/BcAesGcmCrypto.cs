using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;

#pragma warning disable 618

namespace CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos
{
	public class BcAesGcmCrypto : IAEADCrypto
	{
		public string Name => @"AES-GCM";

		private BufferedAeadBlockCipher _engine;
		private readonly KeyParameter _key;
		private readonly IBlockCipher _aes;

		public BcAesGcmCrypto(byte[] key)
		{
			_aes = new AesFastEngine();
			_key = new KeyParameter(key);

			_engine = new BufferedAeadBlockCipher(new GcmBlockCipher(_aes));
		}

		public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
			Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
		{
			var input = ArrayPool<byte>.Shared.Rent(source.Length);
			var output = ArrayPool<byte>.Shared.Rent(destination.Length + tag.Length);
			try
			{
				_engine = new BufferedAeadBlockCipher(new GcmBlockCipher(_aes));
				_engine.Init(true, new AeadParameters(_key, 128, nonce.ToArray(), associatedData.ToArray()));

				source.CopyTo(input);

				_engine.DoFinal(input, 0, source.Length, output, 0);

				output.AsSpan(0, destination.Length).CopyTo(destination);
				output.AsSpan(destination.Length, tag.Length).CopyTo(tag);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(input);
				ArrayPool<byte>.Shared.Return(output);
			}
		}

		public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
			Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
		{
			var input = ArrayPool<byte>.Shared.Rent(source.Length + tag.Length);
			var output = ArrayPool<byte>.Shared.Rent(destination.Length);
			try
			{
				_engine.Init(false, new AeadParameters(_key, 128, nonce.ToArray(), associatedData.ToArray()));

				source.CopyTo(input);
				tag.CopyTo(input.AsSpan(source.Length));

				_engine.DoFinal(input, 0, source.Length + tag.Length, output, 0);

				output.AsSpan(0, destination.Length).CopyTo(destination);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(input);
				ArrayPool<byte>.Shared.Return(output);
			}
		}

		public void Dispose() { }
	}
}
