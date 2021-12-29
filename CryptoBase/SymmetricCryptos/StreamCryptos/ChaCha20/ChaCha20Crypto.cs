using System;
using System.Runtime.InteropServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

public abstract class ChaCha20Crypto : ChaCha20CryptoBase
{
	public override string Name => @"ChaCha20";

	public override int IvSize => 12;

	protected ChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		Reset();
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (key.Length != 32)
		{
			throw new ArgumentException(@"Key length requires 32 bytes");
		}

		State[0] = Sigma32[0];
		State[1] = Sigma32[1];
		State[2] = Sigma32[2];
		State[3] = Sigma32[3];

		var keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.CopyTo(State.AsSpan(4));

		SetIV(iv);
	}

	public sealed override void Reset()
	{
		SetCounter(0);
	}

	protected override unsafe void IncrementCounter(uint* state)
	{
		ChaCha20Utils.IncrementCounter(state);
	}

	public void SetIV(ReadOnlySpan<byte> iv)
	{
		var ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		State[13] = ivSpan[0];
		State[14] = ivSpan[1];
		State[15] = ivSpan[2];
	}

	public void SetCounter(uint counter)
	{
		Index = 0;
		State[12] = counter;
	}
}
