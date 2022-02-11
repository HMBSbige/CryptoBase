using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;

public class BcRC4Crypto : StreamCryptoBase
{
	public override string Name => @"RC4";

	private readonly RC4Engine _rc4;

	public BcRC4Crypto(byte[] key)
	{
		_rc4 = new RC4Engine();
		_rc4.Init(default, new KeyParameter(key));
	}

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_rc4.BcUpdateStream(source, destination);
	}

	public override void Reset()
	{
		_rc4.Reset();
	}
}
