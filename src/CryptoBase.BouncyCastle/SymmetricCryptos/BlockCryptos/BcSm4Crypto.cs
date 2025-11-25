using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.CompilerServices;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;

public sealed class BcSm4Crypto : BlockCrypto16
{
	public override string Name => @"SM4";

	private readonly SM4Engine _encryptionEngine;
	private readonly SM4Engine _decryptionEngine;

	public BcSm4Crypto(ReadOnlySpan<byte> key)
	{
		KeyParameter keyParameter = new(key);

		_encryptionEngine = new SM4Engine();
		_decryptionEngine = new SM4Engine();
		_encryptionEngine.Init(true, keyParameter);
		_decryptionEngine.Init(false, keyParameter);
	}

	public override VectorBuffer16 Encrypt(VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_encryptionEngine.ProcessBlock(source, r);

		return r;
	}

	public override VectorBuffer16 Decrypt(VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_decryptionEngine.ProcessBlock(source, r);

		return r;
	}
}
