using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.Expansion;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;

public class BcAESCFBStreamCrypto : StreamCryptoBase
{
	public override string Name => @"AES-CFB";

	private readonly CfbStreamCipher _cfb;

	public BcAESCFBStreamCrypto(bool isEncrypt, byte[] key, byte[] iv)
	{
		if (iv.Length is not 16)
		{
			throw new ArgumentException(@"IV length must be 16 bytes", nameof(iv));
		}

#pragma warning disable 618
		_cfb = new CfbStreamCipher(new AesFastEngine(), 128);
#pragma warning restore 618

		_cfb.Init(isEncrypt, new ParametersWithIV(new KeyParameter(key), iv));
	}

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Update(source, destination);

		var buffer = ArrayPool<byte>.Shared.Rent(source.Length);
		var outBuffer = ArrayPool<byte>.Shared.Rent(source.Length);
		try
		{
			source.CopyTo(buffer);

			_cfb.ProcessBytes(buffer, 0, source.Length, outBuffer, 0);

			outBuffer.AsSpan(0, source.Length).CopyTo(destination);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
			ArrayPool<byte>.Shared.Return(outBuffer);
		}
	}

	public override void Reset()
	{
		_cfb.Reset();
	}
}
