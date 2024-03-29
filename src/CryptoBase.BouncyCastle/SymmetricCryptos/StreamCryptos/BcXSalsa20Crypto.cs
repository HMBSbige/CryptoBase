using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;

public class BcXSalsa20Crypto : SnuffleCryptoBase
{
	public override string Name => @"XSalsa20";

	public override int IvSize => 24;

	private readonly XSalsa20Engine _engine;

	public BcXSalsa20Crypto(byte[] key, byte[] iv)
	{
		_engine = new XSalsa20Engine();
		_engine.Init(default, new ParametersWithIV(new KeyParameter(key), iv));
	}

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_engine.BcUpdateStream(source, destination);
	}

	public override void Reset()
	{
		_engine.Reset();
	}
}
