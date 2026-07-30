namespace CryptoBase.SymmetricCryptos.StreamCryptos;

/// <summary>
/// Provides an XSalsa20 stream cipher with a 192-bit nonce.
/// </summary>
public class XSalsa20Crypto : Salsa20Crypto
{
	/// <inheritdoc />
	public override string Name => @"XSalsa20";

	/// <inheritdoc />
	public override int IvSize => 24;

	/// <summary>
	/// The required key size, in bytes.
	/// </summary>
	public const int KeySize = 32;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 192-bit nonce.</param>
	public XSalsa20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		Reset();
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IvSize, nameof(iv));

		Span<uint> state = StateSpan;

		state[0] = Sigma32[0];
		state[5] = Sigma32[1];
		state[10] = Sigma32[2];
		state[15] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.Slice(0, 4).CopyTo(state.Slice(1));
		keySpan.Slice(4).CopyTo(state.Slice(11));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		ivSpan.Slice(0, 4).CopyTo(state.Slice(6));

		if (Sse2.IsSupported)
		{
			Salsa20Utils.SalsaRound(state, Rounds);
		}
		else
		{
			Salsa20Utils.SalsaRound(Rounds, state);
		}

		state[1] = state[0];
		state[2] = state[5];
		state[3] = state[10];
		state[4] = state[15];

		state.Slice(6, 4).CopyTo(state.Slice(11));

		state[6] = ivSpan[4];
		state[7] = ivSpan[5];

		state[8] = ivSpan[2];
		state[9] = ivSpan[3];

		state[0] = Sigma32[0];
		state[5] = Sigma32[1];
		state[10] = Sigma32[2];
		state[15] = Sigma32[3];
	}
}
