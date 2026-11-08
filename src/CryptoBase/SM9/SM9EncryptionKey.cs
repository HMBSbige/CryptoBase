using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;

namespace CryptoBase.SM9;

/// <summary>
/// Provides the SM9 private key of a user for decryption and key decapsulation (GB/T 38635.2-2020, GM/T 0044-2016), which the key generation center extracts with <see cref="SM9EncryptionMasterKey.ExtractKey" />.
/// </summary>
/// <remarks>
/// <para>
/// The private key de is a point of G2 in the uncompressed encoding, 0x04 ‖ x ‖ y with each coordinate in Fp2 written as its u-coefficient and then its constant coefficient. The instance holds the ID of the user with it.
/// </para>
/// <para>
/// Decryption takes C1 ‖ C3 ‖ C2 of GM/T 0044.4 with C1 as x ‖ y, or the SM9Cipher of GB/T 41389-2022 (GM/T 0080-2020) in DER with EnType 0, and rejects an empty C2 and any other encoding. Decapsulation takes the point C in the uncompressed encoding.
/// </para>
/// <para>
/// Decryption and decapsulation may run concurrently on one instance; to decrypt or decapsulate repeatedly, keep one instance. Disposal erases the private key and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM9EncryptionKey : IDisposable
{
	private readonly SM9G2PrivateKey _key;
	private readonly byte[] _id;
	private bool _disposed;

	internal SM9EncryptionKey(SM9G2PrivateKey key, byte[] id)
	{
		_key = key;
		_id = id;
	}

	/// <summary>
	/// Gets the length of the private key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PrivateKeyLength => SM9G2.EncodedLength;

	/// <summary>
	/// Imports the private key of a user.
	/// </summary>
	/// <remarks>
	/// The private key must lie in G2 and the master public key on the curve, and the key must belong to <paramref name="id" /> and <paramref name="hid" /> under the master public key.
	/// </remarks>
	/// <param name="privateKey">The private key de in the uncompressed encoding, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <param name="masterPublicKey">The master public key Ppub-e in the uncompressed encoding, exactly <see cref="SM9EncryptionMasterKey.PublicKeyLength" /> bytes long.</param>
	/// <param name="id">The ID of the user.</param>
	/// <param name="hid">The identifier hid of the generating function of the private keys for decryption and key decapsulation of the master key; 0x03 by default.</param>
	/// <returns>An instance that holds the private key and the ID.</returns>
	/// <exception cref="ArgumentException"><paramref name="privateKey" /> or <paramref name="masterPublicKey" /> has the wrong length or is not a valid point, or the private key is not that of <paramref name="id" /> and <paramref name="hid" /> under <paramref name="masterPublicKey" />.</exception>
	public static SM9EncryptionKey ImportPrivateKey(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> masterPublicKey, ReadOnlySpan<byte> id, byte hid = SM9Kgc.EncryptionHid)
	{
		SM9G2PrivateKey key = Import(privateKey, masterPublicKey, id, hid, out _);
		return new SM9EncryptionKey(key, id.ToArray());
	}

	/// <summary>
	/// Writes the private key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PrivateKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateKeyLength, nameof(destination));

		SM9G2.Encode(in _key.Point, destination.Slice(0, PrivateKeyLength));
		return PrivateKeyLength;
	}

	/// <summary>
	/// Recovers the key that <paramref name="encapsulation" /> encapsulates (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 6.2).
	/// </summary>
	/// <remarks>
	/// The method returns <see langword="false" /> if <paramref name="encapsulation" /> is not a point on the curve in the uncompressed encoding or the key it gives is all zero. <see langword="true" /> does not mean that <paramref name="encapsulation" /> was made for this key: another one gives another key, which the protocol must confirm. <paramref name="encapsulation" /> may overlap <paramref name="key" />. If the method returns <see langword="false" /> or throws, <paramref name="key" /> remains unchanged.
	/// </remarks>
	/// <param name="encapsulation">The encapsulation.</param>
	/// <param name="key">The buffer that receives the key; its length is that of the key, which must not be 0.</param>
	/// <returns><see langword="true" /> if the key was recovered; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> is empty.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public bool TryDecapsulate(ReadOnlySpan<byte> encapsulation, Span<byte> key)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (key.IsEmpty)
		{
			throw new ArgumentException("The key must not be empty.", nameof(key));
		}

		Unsafe.SkipInit(out SM3KdfState kdf);

		if (!SM9Encryption.TryStart(encapsulation, _key, _id, ref kdf))
		{
			return false;
		}

		try
		{
			return SM9Encryption.TryWriteKey(in kdf, key);
		}
		finally
		{
			kdf.Clear();
		}
	}

	/// <summary>
	/// Decrypts a ciphertext C1 ‖ C3 ‖ C2 (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 7.2), with C1 as x ‖ y.
	/// </summary>
	/// <remarks>
	/// The method returns <see langword="false" /> if <paramref name="ciphertext" /> is too short to hold a plaintext, C1 is not a point on the curve, K1 is all zero or C3 does not match. It then writes nothing to <paramref name="destination" />, which may overlap <paramref name="ciphertext" />.
	/// </remarks>
	/// <param name="ciphertext">The ciphertext.</param>
	/// <param name="destination">The buffer that receives the plaintext, at least as long as the plaintext: 96 bytes shorter than <paramref name="ciphertext" />.</param>
	/// <param name="bytesWritten">When this method returns <see langword="true" />, the length of the plaintext; otherwise, 0.</param>
	/// <returns><see langword="true" /> if the ciphertext was decrypted; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> destination, out int bytesWritten)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		bytesWritten = 0;

		if (ciphertext.Length <= SM9Encryption.CiphertextOverhead)
		{
			return false;
		}

		int length = ciphertext.Length - SM9Encryption.CiphertextOverhead;
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		Span<byte> c1 = stackalloc byte[SM9G1.EncodedLength];
		c1[0] = 0x04;
		ciphertext.Slice(0, SM9Encryption.PointLength).CopyTo(c1.Slice(1));

		if (!SM9Encryption.Open(c1, ciphertext.Slice(SM9Encryption.PointLength, SM9Encryption.HashLength), ciphertext.Slice(SM9Encryption.CiphertextOverhead), _key, _id, destination))
		{
			return false;
		}

		bytesWritten = length;
		return true;
	}

	/// <summary>
	/// Decrypts the DER of an SM9Cipher (GB/T 41389-2022), which holds C1, C3 and C2 (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 7.2).
	/// </summary>
	/// <remarks>
	/// The method returns <see langword="false" /> if <paramref name="ciphertext" /> is not the DER of an SM9Cipher with EnType 0 and a C2 of at least one byte, C1 is not a point on the curve in the uncompressed encoding, K1 is all zero or C3 does not match. It then writes nothing to <paramref name="destination" />, which may overlap <paramref name="ciphertext" />.
	/// </remarks>
	/// <param name="ciphertext">The ciphertext.</param>
	/// <param name="destination">The buffer that receives the plaintext, at least as long as the C2 of the SM9Cipher; a buffer as long as <paramref name="ciphertext" /> suffices.</param>
	/// <param name="bytesWritten">When this method returns <see langword="true" />, the length of the plaintext; otherwise, 0.</param>
	/// <returns><see langword="true" /> if the ciphertext was decrypted; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool TryDecryptDer(ReadOnlySpan<byte> ciphertext, Span<byte> destination, out int bytesWritten)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		bytesWritten = 0;

		if (!SM9Der.TryReadCipher(ciphertext, out ReadOnlySpan<byte> c1, out ReadOnlySpan<byte> c3, out ReadOnlySpan<byte> c2) || c2.IsEmpty)
		{
			return false;
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, c2.Length, nameof(destination));

		if (!SM9Encryption.Open(c1, c3, c2, _key, _id, destination))
		{
			return false;
		}

		bytesWritten = c2.Length;
		return true;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_key.Dispose();
		_disposed = true;
	}

	// The checks of ImportPrivateKey for the identifier hid: de lies in G2 and Ppub-e on the curve, and de = [ke/(h1 + ke)]P2 just if e(Q, de) = e([h1 + ke]P1, de) = e(P1, P2)^ke = e(Ppub-e, P2) = g for h1 = H1(ID ‖ hid, N) and Q = [h1]P1 + Ppub-e, which is the point at infinity only for an ID that has no key. Returns de, whose lines the first pairing built, with Ppub-e and g.
	[SkipLocalsInit]
	internal static SM9G2PrivateKey Import(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> masterPublicKey, ReadOnlySpan<byte> id, byte hid, out (SM9AffinePoint<SM9Fp> PublicKey, SM9Fp12 G) master)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(privateKey.Length, PrivateKeyLength, nameof(privateKey));
		ArgumentOutOfRangeException.ThrowIfNotEqual(masterPublicKey.Length, SM9EncryptionMasterKey.PublicKeyLength, nameof(masterPublicKey));

		if (!SM9G1.TryDecode(masterPublicKey, out SM9AffinePoint<SM9Fp> publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(masterPublicKey));
		}

		if (!SM9Kgc.TryGetUserPublicKey(id, hid, in publicKey, out SM9AffinePoint<SM9Fp> q))
		{
			ThrowHelper.ThrowInvalidKey(nameof(privateKey));
		}

		Unsafe.SkipInit(out SM9AffinePoint<SM9Fp2> point);
		Unsafe.SkipInit(out SM9Fp12 u);
		SM9G2PrivateKey? key = null;

		try
		{
			if (!SM9G2.TryDecode(privateKey, out point))
			{
				ThrowHelper.ThrowInvalidKey(nameof(privateKey));
			}

			key = new SM9G2PrivateKey(in point);
			SM9Pairing.Pair(in publicKey, in SM9G2.Generator, out SM9Fp12 g);
			key.PairVariableTime(in q, out u);

			if (SM9GT.AreEqual(in u, in g) is 0)
			{
				ThrowHelper.ThrowInvalidKey(nameof(privateKey));
			}

			master = (publicKey, g);
			SM9G2PrivateKey imported = key;
			key = null;
			return imported;
		}
		finally
		{
			key?.Dispose();
			point.ZeroMemory();
			u.ZeroMemory();
		}
	}
}
