namespace CryptoBase.SymmetricCryptos.StreamCryptos;

/// <summary>
/// Provides an XChaCha20 stream cipher with a 192-bit nonce.
/// </summary>
public class XChaCha20Crypto : ChaCha20OriginalCrypto
{
	/// <inheritdoc />
	public override string Name => @"XChaCha20";

	/// <inheritdoc />
	public override int IVSize => 24;

	/// <summary>
	/// The required key size, in bytes.
	/// </summary>
	public const int KeySize = 32;

	private VectorBuffer32 _key;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 192-bit nonce.</param>
	public XChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		_key = key.AsVectorBuffer32();

		SetIV(iv);
		SetCounter(0);
	}

	private void ChaChaRound(Span<uint> x)
	{
		if (Sse2.IsSupported)
		{
			ChaCha20Utils.ChaChaRound(x, Rounds);
		}
		else
		{
			ChaCha20Utils.ChaChaRound(Rounds, x);
		}
	}

	/// <summary>
	/// Sets the 192-bit nonce.
	/// </summary>
	/// <param name="iv">The nonce.</param>
	public sealed override void SetIV(ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		Span<uint> state = StateSpan;
		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(_key.AsSpan());
		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);

		Sigma32.CopyTo(state);
		keySpan.CopyTo(state.Slice(4));
		ivSpan.Slice(0, 4).CopyTo(state.Slice(12));

		ChaChaRound(state);

		state.Slice(12).CopyTo(state.Slice(8));
		state.Slice(0, 4).CopyTo(state.Slice(4));
		Sigma32.CopyTo(state);

		state[14] = ivSpan[4];
		state[15] = ivSpan[5];
	}

	/// <inheritdoc />
	public override void Dispose()
	{
		_key.ZeroMemory();
		base.Dispose();
		GC.SuppressFinalize(this);
	}
}
