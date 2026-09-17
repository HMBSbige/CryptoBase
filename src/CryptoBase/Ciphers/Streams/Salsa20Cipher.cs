namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// Implements the Salsa20 stream cipher.
/// </summary>
public class Salsa20Cipher : SnuffleCipher
{
	/// <summary>The required nonce size, in bytes.</summary>
	public const int IVSize = 8;

	/// <summary>
	/// Initializes a Salsa20 cipher with the specified key and initialization vector.
	/// </summary>
	/// <param name="key">The 16- or 32-byte key.</param>
	/// <param name="iv">The 8-byte initialization vector.</param>
	public Salsa20Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		SetCounter(0);
	}

	private protected Salsa20Cipher()
	{
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		int keyLength = key.Length;

		Span<uint> state = StateSpan;

		switch (keyLength)
		{
			case 16:
			{
				state[0] = Sigma16[0];
				state[5] = Sigma16[1];
				state[10] = Sigma16[2];
				state[15] = Sigma16[3];
				state[11] = keySpan[0];
				state[12] = keySpan[1];
				state[13] = keySpan[2];
				state[14] = keySpan[3];
				break;
			}
			case 32:
			{
				state[0] = Sigma32[0];
				state[5] = Sigma32[1];
				state[10] = Sigma32[2];
				state[15] = Sigma32[3];
				state[11] = keySpan[4];
				state[12] = keySpan[5];
				state[13] = keySpan[6];
				state[14] = keySpan[7];
				break;
			}
			default:
			{
				ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key));
				return;
			}
		}

		state[1] = keySpan[0];
		state[2] = keySpan[1];
		state[3] = keySpan[2];
		state[4] = keySpan[3];

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		state[6] = ivSpan[0];
		state[7] = ivSpan[1];
	}

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++Salsa20Utils.GetCounter(ref state.GetReference());
	}

	/// <summary>Sets the block counter and resets the byte offset within the block to zero.</summary>
	/// <param name="counter">The counter value for the next 64-byte keystream block.</param>
	public void SetCounter(ulong counter)
	{
		CounterRemaining = MaxCounter - counter;
		Index = 0;
		Salsa20Utils.GetCounter(ref StateRef) = counter;
	}

	/// <inheritdoc />
	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		return Salsa20Utils.XorBlocks(stateSpan, source, destination);
	}

	/// <inheritdoc />
	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(Rounds, StateSpan, KeyStreamSpan);
	}
}
