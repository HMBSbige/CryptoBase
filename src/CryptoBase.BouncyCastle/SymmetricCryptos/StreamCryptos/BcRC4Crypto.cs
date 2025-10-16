using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;

public class BcRC4Crypto : StreamCryptoBase
{
	public override string Name => @"RC4";

	private readonly RC4Engine _engine;

	public BcRC4Crypto(ReadOnlySpan<byte> key)
	{
		_engine = new RC4Engine();
		_engine.Init(default, new KeyParameter(key));
	}

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_engine.ProcessBytes(source, destination);
	}

	public override void Reset()
	{
		_engine.Reset();
	}
}
