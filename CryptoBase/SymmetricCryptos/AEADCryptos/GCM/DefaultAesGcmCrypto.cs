using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.AEADCryptos.GCM
{
	public class DefaultAesGcmCrypto : IAEADCrypto
	{
		public string Name => @"AES-GCM";

		private readonly AesGcm _internalCrypto;

		public const int NonceSize = 12;

		public DefaultAesGcmCrypto(ReadOnlySpan<byte> key)
		{
			_internalCrypto = new AesGcm(key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
			Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
		{
			_internalCrypto.Encrypt(nonce, source, destination, tag, associatedData);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
			Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
		{
			_internalCrypto.Decrypt(nonce, source, tag, destination, associatedData);
		}

		public void Dispose()
		{
			_internalCrypto.Dispose();
		}
	}
}
