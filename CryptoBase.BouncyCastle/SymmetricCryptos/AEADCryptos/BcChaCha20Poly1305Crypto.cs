using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos
{
	public class BcChaCha20Poly1305Crypto : IAEADCrypto
	{
		public string Name => @"ChaCha20-Poly1305";

		private BufferedAeadCipher _engine;
		private readonly KeyParameter _key;

		public BcChaCha20Poly1305Crypto(byte[] key)
		{
			_key = new KeyParameter(key);
			_engine = new BufferedAeadCipher(new ChaCha20Poly1305());
		}

		public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
			Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
		{
			var input = ArrayPool<byte>.Shared.Rent(source.Length);
			var output = ArrayPool<byte>.Shared.Rent(destination.Length + tag.Length);
			try
			{
				_engine = new BufferedAeadCipher(new ChaCha20Poly1305());
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
