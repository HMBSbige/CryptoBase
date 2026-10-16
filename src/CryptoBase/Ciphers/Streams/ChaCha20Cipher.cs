using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8439
/// </summary>
public class ChaCha20Cipher : SnuffleCipher
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = 32;

	/// <summary>The required nonce size, in bytes.</summary>
	public const int IVSize = 12;

	/// <inheritdoc />
	protected override ulong MaxCounter => uint.MaxValue;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 96-bit nonce.</param>
	public ChaCha20Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		Span<uint> state = StateSpan;
		state[0] = Sigma32[0];
		state[1] = Sigma32[1];
		state[2] = Sigma32[2];
		state[3] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.CopyTo(state.Slice(4));

		InitializeNonce(iv);
	}

	/// <inheritdoc />
	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		return XorBlocks(stateSpan, source, destination);
	}

	// ChaCha20Utils.XorBlocks advances words 12-13 as one 64-bit counter; undo its carry into nonce word 13 after block 0xFFFFFFFF.
	private static int XorBlocks(Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		uint nonce0 = state[13];
		int processed = ChaCha20Utils.XorBlocks(state, source, destination);
		state[13] = nonce0;
		return processed;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.NoInlining)]
	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, StateSpan, KeyStreamSpan);
	}

	internal void XorWholeBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(Index is 0 && source.Length % BlockSize is 0 && destination.Length >= source.Length);
		Debug.Assert((ulong)source.Length / BlockSize <= CounterRemaining);

		XorBlocks(StateSpan, source, destination);
		CounterRemaining -= (uint)source.Length / BlockSize;
	}

	internal int XorChunksAndAppendPoly1305<TState>(ReadOnlySpan<byte> source, Span<byte> destination, ref TState mac, int processed, ref int hashedLength, bool decrypt) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Debug.Assert(Index is 0 && destination.Length >= source.Length);

		int end = ChaCha20Utils.XorPoly1305(ref StateRef, ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length, ref mac, processed, ref hashedLength, decrypt);
		Debug.Assert((ulong)(end - processed + BlockSize - 1) / BlockSize <= CounterRemaining);
		CounterRemaining -= (uint)(end - processed + BlockSize - 1) / BlockSize;
		return end;
	}

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounter(ref MemoryMarshal.GetReference(state));
	}

	/// <summary>Initializes the nonce and resets the block counter to zero.</summary>
	internal void InitializeNonce(ReadOnlySpan<byte> nonce)
	{
		Debug.Assert(nonce.Length is IVSize);

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(nonce);
		Span<uint> state = StateSpan;
		state[13] = ivSpan[0];
		state[14] = ivSpan[1];
		state[15] = ivSpan[2];
		SetCounter(0);
	}

	/// <summary>Sets the block counter and resets the byte offset within the block to zero.</summary>
	/// <param name="counter">The counter value for the next 64-byte keystream block.</param>
	public void SetCounter(uint counter)
	{
		CounterRemaining = GetBlocksRemaining(counter);
		Index = 0;
		ChaCha20Utils.GetCounter(ref StateRef) = counter;
	}
}
