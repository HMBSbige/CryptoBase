using CryptoBase.EllipticCurves.SM9;

namespace CryptoBase.SM9;

/// <summary>
/// Provides the SM9 private key of a user for the key exchange of <see cref="SM9KeyExchange" /> (GB/T 38635.2-2020, GM/T 0044-2016), which the key generation center extracts with <see cref="SM9EncryptionMasterKey.ExtractKeyExchangeKey" />.
/// </summary>
/// <remarks>
/// <para>
/// The private key de is a point of G2 in the uncompressed encoding, 0x04 ‖ x ‖ y with each coordinate in Fp2 written as its u-coefficient and then its constant coefficient, and the instance holds with it the ID of the user, the encryption master public key and the identifier hid of the generating function, which the key of the peer must share.
/// The key generation center chooses the hid of the key exchange, 0x02 by default; with a hid other than that of decryption, the key differs from the decryption key of the same ID.
/// </para>
/// <para>
/// Key exchanges may run concurrently with one instance; to run many key exchanges, keep one instance. Disposal erases the private key and is idempotent; subsequent operations other than disposal, and the derivations of the key exchanges that take the key, throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM9KeyExchangeKey : IDisposable
{
	private readonly SM9G2PrivateKey _key;
	private readonly byte[] _id;
	// g = e(Ppub-e, P2), once an import or key exchange has computed it.
	private SM9GTBase? _base;
	private bool _disposed;

	internal SM9KeyExchangeKey(SM9G2PrivateKey key, in SM9AffinePoint<SM9Fp> masterPublicKey, byte[] id, byte hid, SM9GTBase? gtBase)
	{
		_key = key;
		MasterPublicKey = new SM9G1FixedBase(in masterPublicKey, false);
		_id = id;
		Hid = hid;
		_base = gtBase;
	}

	/// <summary>
	/// Gets the length of the private key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PrivateKeyLength => SM9G2.EncodedLength;

	internal ReadOnlySpan<byte> Id => _id;

	// The identifier hid of the generating function, which the user public key of the peer takes too.
	internal byte Hid { get; }

	// Ppub-e, with the table of its products from the key exchanges that SM9G1FixedBase sets on.
	internal SM9G1FixedBase MasterPublicKey { get; }

	/// <summary>
	/// Imports the private key of a user.
	/// </summary>
	/// <remarks>
	/// The private key must lie in G2 and the master public key on the curve, and the key must belong to <paramref name="id" /> and <paramref name="hid" /> under the master public key.
	/// </remarks>
	/// <param name="privateKey">The private key de in the uncompressed encoding, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <param name="masterPublicKey">The master public key Ppub-e in the uncompressed encoding, exactly <see cref="SM9EncryptionMasterKey.PublicKeyLength" /> bytes long.</param>
	/// <param name="id">The ID of the user.</param>
	/// <param name="hid">The identifier hid of the generating function of the key exchange keys; 0x02 by default.</param>
	/// <returns>An instance that holds the private key, the ID, the master public key and the hid.</returns>
	/// <exception cref="ArgumentException"><paramref name="privateKey" /> or <paramref name="masterPublicKey" /> has the wrong length or is not a valid point, or the private key is not that of <paramref name="id" /> and <paramref name="hid" /> under <paramref name="masterPublicKey" />.</exception>
	public static SM9KeyExchangeKey ImportPrivateKey(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> masterPublicKey, ReadOnlySpan<byte> id, byte hid = SM9Kgc.KeyExchangeHid)
	{
		SM9G2PrivateKey key = SM9EncryptionKey.Import(privateKey, masterPublicKey, id, hid, out (SM9AffinePoint<SM9Fp> PublicKey, SM9Fp12 G) master);
		return new SM9KeyExchangeKey(key, in master.PublicKey, id.ToArray(), hid, new SM9GTBase(in master.G));
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

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_key.Dispose();
		_base?.Dispose();
		_base = null;
		_disposed = true;
	}

	// The private key, whose lines the pairings of a key exchange take.
	internal SM9G2PrivateKey GetKey()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key;
	}

	// g = e(Ppub-e, P2).
	internal SM9GTBase GetBase()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _base ?? SM9GTBase.Publish(ref _base, in MasterPublicKey.Point, in SM9G2.Generator);
	}
}
