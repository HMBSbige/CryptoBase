using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

[StructLayout(LayoutKind.Sequential, Size = RoundKeyCount * RoundKeySize)]
public struct Aes128CryptoX86 : IBlockCrypto
{
	private const int RoundKeyCount = 20;
	private const int RoundKeySize = 0x10;

	private Vector128<byte> _roundKeys;

	private readonly ReadOnlySpan<Vector128<byte>> RoundKeys => MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(in _roundKeys), RoundKeyCount);

	public Aes128CryptoX86(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 16, nameof(key));
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> KeyRound(Vector128<byte> key, [ConstantExpected] byte rcon)
	{
		Vector128<byte> t = Aes.KeygenAssist(key, rcon);
		t = Sse2.Shuffle(t.AsUInt32(), 0b11_11_11_11).AsByte();

		key ^= Sse2.ShiftLeftLogical128BitLane(key, 4);
		key ^= Sse2.ShiftLeftLogical128BitLane(key, 8);

		return key ^ t;
	}

	private void Init(ReadOnlySpan<byte> key)
	{
		Span<Vector128<byte>> roundKeys = MemoryMarshal.CreateSpan(ref _roundKeys, RoundKeyCount);

		roundKeys[0] = Vector128.Create(key);
		roundKeys[1] = KeyRound(roundKeys[0], AESUtils.Rcon1);
		roundKeys[2] = KeyRound(roundKeys[1], AESUtils.Rcon2);
		roundKeys[3] = KeyRound(roundKeys[2], AESUtils.Rcon3);
		roundKeys[4] = KeyRound(roundKeys[3], AESUtils.Rcon4);
		roundKeys[5] = KeyRound(roundKeys[4], AESUtils.Rcon5);
		roundKeys[6] = KeyRound(roundKeys[5], AESUtils.Rcon6);
		roundKeys[7] = KeyRound(roundKeys[6], AESUtils.Rcon7);
		roundKeys[8] = KeyRound(roundKeys[7], AESUtils.Rcon8);
		roundKeys[9] = KeyRound(roundKeys[8], AESUtils.Rcon9);
		roundKeys[10] = KeyRound(roundKeys[9], AESUtils.Rcon10);

		roundKeys[11] = Aes.InverseMixColumns(roundKeys[9]);
		roundKeys[12] = Aes.InverseMixColumns(roundKeys[8]);
		roundKeys[13] = Aes.InverseMixColumns(roundKeys[7]);
		roundKeys[14] = Aes.InverseMixColumns(roundKeys[6]);
		roundKeys[15] = Aes.InverseMixColumns(roundKeys[5]);
		roundKeys[16] = Aes.InverseMixColumns(roundKeys[4]);
		roundKeys[17] = Aes.InverseMixColumns(roundKeys[3]);
		roundKeys[18] = Aes.InverseMixColumns(roundKeys[2]);
		roundKeys[19] = Aes.InverseMixColumns(roundKeys[1]);
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
		return Aes.EncryptLast(b, keys[10]);
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

		Vector128<byte> b = input ^ keys[10];
		b = Aes.Decrypt(b, keys[11]);
		b = Aes.Decrypt(b, keys[12]);
		b = Aes.Decrypt(b, keys[13]);
		b = Aes.Decrypt(b, keys[14]);
		b = Aes.Decrypt(b, keys[15]);
		b = Aes.Decrypt(b, keys[16]);
		b = Aes.Decrypt(b, keys[17]);
		b = Aes.Decrypt(b, keys[18]);
		b = Aes.Decrypt(b, keys[19]);
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
