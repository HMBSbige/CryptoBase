using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

[StructLayout(LayoutKind.Sequential, Size = RoundKeyCount * RoundKeySize)]
public struct Aes256CryptoX86 : IBlockCrypto
{
	private const int RoundKeyCount = 28;
	private const int RoundKeySize = 0x10;

	private Vector128<byte> _roundKeys;

	private readonly ReadOnlySpan<Vector128<byte>> RoundKeys => MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(in _roundKeys), RoundKeyCount);

	public Aes256CryptoX86(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32, nameof(key));
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound1(ref Vector128<byte> a, ref Vector128<byte> b)
	{
		Vector128<byte> t = Sse2.ShiftLeftLogical128BitLane(a, 4);
		b = Sse2.Shuffle(b.AsUInt32(), 0b11_11_11_11).AsByte();
		a ^= t;
		t = Sse2.ShiftLeftLogical128BitLane(t, 4);
		a ^= t;
		t = Sse2.ShiftLeftLogical128BitLane(t, 4);
		a ^= t;
		a ^= b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound2(ref Vector128<byte> a, ref Vector128<byte> b)
	{
		Vector128<byte> t0 = Aes.KeygenAssist(a, AESUtils.Rcon0);
		Vector128<byte> t1 = Sse2.Shuffle(t0.AsUInt32(), 0b10_10_10_10).AsByte();

		t0 = Sse2.ShiftLeftLogical128BitLane(b, 4);
		b ^= t0;
		t0 = Sse2.ShiftLeftLogical128BitLane(t0, 4);
		b ^= t0;
		t0 = Sse2.ShiftLeftLogical128BitLane(t0, 4);
		b ^= t0;
		b ^= t1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound(out Vector128<byte> a, out Vector128<byte> b,
		ref Vector128<byte> t0, ref Vector128<byte> t1, [ConstantExpected] byte rcon)
	{
		a = t1;
		Vector128<byte> t2 = Aes.KeygenAssist(t1, rcon);
		KeyRound1(ref t0, ref t2);
		b = t0;
		KeyRound2(ref t0, ref t1);
	}

	private void Init(ReadOnlySpan<byte> key)
	{
		Span<Vector128<byte>> roundKeys = MemoryMarshal.CreateSpan(ref _roundKeys, RoundKeyCount);

		Vector128<byte> t0 = Vector128.Create(key);// 0,15
		Vector128<byte> t1 = Vector128.Create(key[16..]);// 15,31

		roundKeys[0] = t0;

		KeyRound(out roundKeys[1], out roundKeys[2], ref t0, ref t1, AESUtils.Rcon1);
		KeyRound(out roundKeys[3], out roundKeys[4], ref t0, ref t1, AESUtils.Rcon2);
		KeyRound(out roundKeys[5], out roundKeys[6], ref t0, ref t1, AESUtils.Rcon3);
		KeyRound(out roundKeys[7], out roundKeys[8], ref t0, ref t1, AESUtils.Rcon4);
		KeyRound(out roundKeys[9], out roundKeys[10], ref t0, ref t1, AESUtils.Rcon5);
		KeyRound(out roundKeys[11], out roundKeys[12], ref t0, ref t1, AESUtils.Rcon6);

		roundKeys[13] = t1;
		Vector128<byte> t2 = Aes.KeygenAssist(t1, AESUtils.Rcon7);
		KeyRound1(ref t0, ref t2);
		roundKeys[14] = t0;

		roundKeys[15] = Aes.InverseMixColumns(roundKeys[13]);
		roundKeys[16] = Aes.InverseMixColumns(roundKeys[12]);
		roundKeys[17] = Aes.InverseMixColumns(roundKeys[11]);
		roundKeys[18] = Aes.InverseMixColumns(roundKeys[10]);
		roundKeys[19] = Aes.InverseMixColumns(roundKeys[9]);
		roundKeys[20] = Aes.InverseMixColumns(roundKeys[8]);
		roundKeys[21] = Aes.InverseMixColumns(roundKeys[7]);
		roundKeys[22] = Aes.InverseMixColumns(roundKeys[6]);
		roundKeys[23] = Aes.InverseMixColumns(roundKeys[5]);
		roundKeys[24] = Aes.InverseMixColumns(roundKeys[4]);
		roundKeys[25] = Aes.InverseMixColumns(roundKeys[3]);
		roundKeys[26] = Aes.InverseMixColumns(roundKeys[2]);
		roundKeys[27] = Aes.InverseMixColumns(roundKeys[1]);
	}

	public readonly void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));

		Vector128<byte> t = Vector128.Create(source);
		EncryptBlock(t).CopyTo(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly Vector128<byte> EncryptBlock(Vector128<byte> input)
	{
		ReadOnlySpan<Vector128<byte>> keys = RoundKeys;

		Vector128<byte> b = input ^ keys[0];
		b = Aes.Encrypt(b, keys[1]);
		b = Aes.Encrypt(b, keys[2]);
		b = Aes.Encrypt(b, keys[3]);
		b = Aes.Encrypt(b, keys[4]);
		b = Aes.Encrypt(b, keys[5]);
		b = Aes.Encrypt(b, keys[6]);
		b = Aes.Encrypt(b, keys[7]);
		b = Aes.Encrypt(b, keys[8]);
		b = Aes.Encrypt(b, keys[9]);
		b = Aes.Encrypt(b, keys[10]);
		b = Aes.Encrypt(b, keys[11]);
		b = Aes.Encrypt(b, keys[12]);
		b = Aes.Encrypt(b, keys[13]);
		return Aes.EncryptLast(b, keys[14]);
	}

	public readonly void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));

		Vector128<byte> t = Vector128.Create(source);
		DecryptBlock(t).CopyTo(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly Vector128<byte> DecryptBlock(Vector128<byte> input)
	{
		ReadOnlySpan<Vector128<byte>> keys = RoundKeys;

		Vector128<byte> b = input ^ keys[14];
		b = Aes.Decrypt(b, keys[15]);
		b = Aes.Decrypt(b, keys[16]);
		b = Aes.Decrypt(b, keys[17]);
		b = Aes.Decrypt(b, keys[18]);
		b = Aes.Decrypt(b, keys[19]);
		b = Aes.Decrypt(b, keys[20]);
		b = Aes.Decrypt(b, keys[21]);
		b = Aes.Decrypt(b, keys[22]);
		b = Aes.Decrypt(b, keys[23]);
		b = Aes.Decrypt(b, keys[24]);
		b = Aes.Decrypt(b, keys[25]);
		b = Aes.Decrypt(b, keys[26]);
		b = Aes.Decrypt(b, keys[27]);
		return Aes.DecryptLast(b, keys[0]);
	}

	public readonly int BlockSize => 16;

	public readonly string Name => "AES";

	public void Reset()
	{
	}

	public void Dispose()
	{
	}
}
