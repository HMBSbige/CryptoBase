using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

[StructLayout(LayoutKind.Sequential, Size = RoundKeyCount * RoundKeySize)]
public struct Aes192CryptoX86 : IBlockCrypto
{
	private const int RoundKeyCount = 24;
	private const int RoundKeySize = 0x10;

	private Vector128<byte> _roundKeys;

	private readonly ReadOnlySpan<Vector128<byte>> RoundKeys => MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(in _roundKeys), RoundKeyCount);

	public Aes192CryptoX86(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 24, nameof(key));
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound(ref Vector128<byte> a, ref Vector128<byte> b, ref Vector128<byte> c)
	{
		Vector128<byte> t = Sse2.ShiftLeftLogical128BitLane(a, 4);
		b = Sse2.Shuffle(b.AsUInt32(), 0b01_01_01_01).AsByte();
		a ^= t;
		t = Sse2.ShiftLeftLogical128BitLane(t, 4);
		a ^= t;
		t = Sse2.ShiftLeftLogical128BitLane(t, 4);
		a ^= t;
		a ^= b;
		b = Sse2.Shuffle(a.AsUInt32(), 0b11_11_11_11).AsByte();
		t = Sse2.ShiftLeftLogical128BitLane(c, 4);
		c ^= t;
		c ^= b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound(
		out Vector128<byte> a, out Vector128<byte> b, out Vector128<byte> c,
		ref Vector128<byte> t0, ref Vector128<byte> t1,
		[ConstantExpected] byte rcon0, [ConstantExpected] byte rcon1)
	{
		a = t0;
		b = t1;
		Vector128<byte> t2 = Aes.KeygenAssist(t1, rcon0);
		KeyRound(ref t0, ref t2, ref t1);

		b = Sse2.Shuffle(b.AsDouble(), t0.AsDouble(), 0).AsByte();
		c = Sse2.Shuffle(t0.AsDouble(), t1.AsDouble(), 1).AsByte();
		t2 = Aes.KeygenAssist(t1, rcon1);
		KeyRound(ref t0, ref t2, ref t1);
	}

	private void Init(ReadOnlySpan<byte> key)
	{
		Span<Vector128<byte>> roundKeys = MemoryMarshal.CreateSpan(ref _roundKeys, RoundKeyCount);

		Vector128<byte> t0 = Vector128.Create(key);// 0,15
		Vector128<byte> t1 = Vector128.Create(Vector64.Create(key[16..]), Vector64<byte>.Zero);// 16,23

		KeyRound(out roundKeys[0], out roundKeys[1], out roundKeys[2], ref t0, ref t1, AESUtils.Rcon1, AESUtils.Rcon2);
		KeyRound(out roundKeys[3], out roundKeys[4], out roundKeys[5], ref t0, ref t1, AESUtils.Rcon3, AESUtils.Rcon4);
		KeyRound(out roundKeys[6], out roundKeys[7], out roundKeys[8], ref t0, ref t1, AESUtils.Rcon5, AESUtils.Rcon6);
		KeyRound(out roundKeys[9], out roundKeys[10], out roundKeys[11], ref t0, ref t1, AESUtils.Rcon7, AESUtils.Rcon8);
		roundKeys[12] = t0;

		roundKeys[13] = Aes.InverseMixColumns(roundKeys[11]);
		roundKeys[14] = Aes.InverseMixColumns(roundKeys[10]);
		roundKeys[15] = Aes.InverseMixColumns(roundKeys[9]);
		roundKeys[16] = Aes.InverseMixColumns(roundKeys[8]);
		roundKeys[17] = Aes.InverseMixColumns(roundKeys[7]);
		roundKeys[18] = Aes.InverseMixColumns(roundKeys[6]);
		roundKeys[19] = Aes.InverseMixColumns(roundKeys[5]);
		roundKeys[20] = Aes.InverseMixColumns(roundKeys[4]);
		roundKeys[21] = Aes.InverseMixColumns(roundKeys[3]);
		roundKeys[22] = Aes.InverseMixColumns(roundKeys[2]);
		roundKeys[23] = Aes.InverseMixColumns(roundKeys[1]);
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
		return Aes.EncryptLast(b, keys[12]);
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

		Vector128<byte> b = input ^ keys[12];
		b = Aes.Decrypt(b, keys[13]);
		b = Aes.Decrypt(b, keys[14]);
		b = Aes.Decrypt(b, keys[15]);
		b = Aes.Decrypt(b, keys[16]);
		b = Aes.Decrypt(b, keys[17]);
		b = Aes.Decrypt(b, keys[18]);
		b = Aes.Decrypt(b, keys[19]);
		b = Aes.Decrypt(b, keys[20]);
		b = Aes.Decrypt(b, keys[21]);
		b = Aes.Decrypt(b, keys[22]);
		b = Aes.Decrypt(b, keys[23]);
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
