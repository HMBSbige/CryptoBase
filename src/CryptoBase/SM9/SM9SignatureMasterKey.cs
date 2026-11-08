using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;

namespace CryptoBase.SM9;

/// <summary>
/// Provides an SM9 signature master key (GB/T 38635.2-2020, GM/T 0044-2016): the extraction of the signing keys of users by the key generation center, and the verification of their signatures.
/// </summary>
/// <remarks>
/// <para>
/// The master private key ks is big-endian and must lie in [1, N − 1]. The master public key Ppub-s = [ks]P2 is a point of G2 in the uncompressed encoding, 0x04 ‖ x ‖ y with each coordinate in Fp2 written as its u-coefficient and then its constant coefficient, and must lie in G2.
/// An instance that holds only the master public key verifies; extracting keys needs the master private key. Extraction and verification may run concurrently on one instance.
/// </para>
/// <para>
/// A signature is h ‖ S of GM/T 0044.2, 97 bytes with S uncompressed, or the SM9Signature of GB/T 41389-2022 (GM/T 0080-2020) in DER. Verification rejects any other encoding.
/// </para>
/// <para>
/// The key generation center chooses the identifier hid of the generating function of the signing keys and publishes it with the master public key. The instance holds it, 0x01 by default as GB/T 41389-2022 gives it, and takes it for extraction and verification, so a verifier imports the master public key with the hid of the master key that extracted the keys of the signers.
/// </para>
/// <para>
/// To verify many signatures, keep one instance rather than import the key for each. Disposal erases the master private key and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM9SignatureMasterKey : IDisposable
{
	// ks, plain.
	private FieldElement<SM9Order> _privateKey;
	private SM9AffinePoint<SM9Fp2> _publicKey;
	private bool _hasPrivateKey;
	private readonly byte _hid;
	// The lines of the pairings with Ppub-s, once a verification has computed them.
	private SM9PairingLines? _lines;
	private bool _disposed;

	private SM9SignatureMasterKey(byte hid)
	{
		_hid = hid;
	}

	/// <summary>
	/// Gets the length of the master private key, in bytes.
	/// </summary>
	public static int PrivateKeyLength => SM9Kgc.PrivateKeyLength;

	/// <summary>
	/// Gets the length of the master public key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PublicKeyLength => SM9G2.EncodedLength;

	/// <summary>
	/// Gets a value that indicates whether the instance holds the master private key.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool HasPrivateKey
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _hasPrivateKey;
		}
	}

	/// <summary>
	/// Gets the identifier hid of the generating function of the signing keys, which extraction and verification take.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public byte Hid
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _hid;
		}
	}

	/// <summary>
	/// Generates a master key from a new random master private key.
	/// </summary>
	/// <param name="hid">The identifier hid of the generating function of the signing keys; 0x01 by default.</param>
	/// <returns>An instance that holds the master private key and the master public key.</returns>
	public static SM9SignatureMasterKey GenerateKey(byte hid = SM9Kgc.SignatureHid)
	{
		return GenerateKey(SystemRandom.Fill, hid);
	}

	/// <summary>
	/// Imports a master private key.
	/// </summary>
	/// <param name="source">The master private key as big-endian bytes, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <param name="hid">The identifier hid of the generating function of the signing keys; 0x01 by default.</param>
	/// <returns>An instance that holds the master private key and the master public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not in [1, N − 1].</exception>
	public static SM9SignatureMasterKey ImportPrivateKey(ReadOnlySpan<byte> source, byte hid = SM9Kgc.SignatureHid)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		if (!FieldElement<SM9Order>.TryImportNonzero(source, out FieldElement<SM9Order> privateKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		SM9SignatureMasterKey key = new(hid);
		key.SetPrivateKey(in privateKey);
		privateKey.ZeroMemory();
		return key;
	}

	/// <summary>
	/// Imports a master public key.
	/// </summary>
	/// <param name="source">The master public key in the uncompressed encoding, exactly <see cref="PublicKeyLength" /> bytes long.</param>
	/// <param name="hid">The identifier hid of the generating function of the signing keys; 0x01 by default.</param>
	/// <returns>An instance that holds only the master public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a point of G2.</exception>
	public static SM9SignatureMasterKey ImportPublicKey(ReadOnlySpan<byte> source, byte hid = SM9Kgc.SignatureHid)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PublicKeyLength, nameof(source));

		if (!SM9G2.TryDecode(source, out SM9AffinePoint<SM9Fp2> publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		return new SM9SignatureMasterKey(hid) { _publicKey = publicKey };
	}

	/// <summary>
	/// Writes the master private key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PrivateKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the master private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPrivateKey(Span<byte> destination)
	{
		ThrowIfNoPrivateKey();
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateKeyLength, nameof(destination));

		FieldElement<SM9Order>.Export(in _privateKey, destination.Slice(0, PrivateKeyLength));
		return PrivateKeyLength;
	}

	/// <summary>
	/// Writes the master public key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PublicKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPublicKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PublicKeyLength, nameof(destination));

		SM9G2.Encode(in _publicKey, destination.Slice(0, PublicKeyLength));
		return PublicKeyLength;
	}

	/// <summary>
	/// Extracts the signing key of a user (GB/T 38635.2-2020, GM/T 0044.2-2016, Sec. 5.3).
	/// </summary>
	/// <param name="id">The ID of the user, which may have any length.</param>
	/// <returns>The signing key of the user, which holds the master public key.</returns>
	/// <exception cref="CryptographicException">No key exists for <paramref name="id" /> under the master key and its hid; GM/T 0044 has the key generation center generate a new master key in that case.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the master private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public SM9SignatureKey ExtractKey(ReadOnlySpan<byte> id)
	{
		ThrowIfNoPrivateKey();

		Unsafe.SkipInit(out FieldElement<SM9Order> scalar);
		Unsafe.SkipInit(out SM9AffinePoint<SM9Fp> privateKey);

		try
		{
			// dsA = [t2]P1.
			SM9Kgc.ExtractScalar(in _privateKey, id, _hid, out scalar);
			SM9G1.MultiplyBase(in scalar, out privateKey);
			return new SM9SignatureKey(in privateKey, in _publicKey, null);
		}
		finally
		{
			scalar.ZeroMemory();
			privateKey.ZeroMemory();
		}
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature h ‖ S of <paramref name="message" /> by the user of <paramref name="id" /> (GB/T 38635.2-2020, GM/T 0044.2-2016, Sec. 7.1).
	/// </summary>
	/// <param name="message">The message.</param>
	/// <param name="signature">The signature h ‖ S, with S uncompressed.</param>
	/// <param name="id">The ID of the signer.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> id)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (signature.Length != SM9SignatureKey.SignatureLength)
		{
			return false;
		}

		return Verify(message, signature.Slice(0, SM9SignatureKey.HashLength), signature.Slice(SM9SignatureKey.HashLength), id);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is an SM9Signature (GB/T 41389-2022) of <paramref name="message" /> by the user of <paramref name="id" /> (GB/T 38635.2-2020, GM/T 0044.2-2016, Sec. 7.1).
	/// </summary>
	/// <param name="message">The message.</param>
	/// <param name="signature">The signature in DER.</param>
	/// <param name="id">The ID of the signer.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool VerifyDer(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> id)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return SM9Der.TryReadSignature(signature, out ReadOnlySpan<byte> h, out ReadOnlySpan<byte> s) && Verify(message, h, s, id);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_privateKey.ZeroMemory();
		_hasPrivateKey = false;
		_lines = null;
		_disposed = true;
	}

	// GenerateKey with the randomness of fill. If fill throws, nothing is left behind.
	[SkipLocalsInit]
	internal static SM9SignatureMasterKey GenerateKey(Action<Span<byte>> fill, byte hid)
	{
		Unsafe.SkipInit(out FieldElement<SM9Order> privateKey);

		try
		{
			SM9Kgc.GenerateScalar(fill, out privateKey);
			SM9SignatureMasterKey key = new(hid);
			key.SetPrivateKey(in privateKey);
			return key;
		}
		finally
		{
			privateKey.ZeroMemory();
		}
	}

	// GB/T 38635.2-2020, Sec. 7.1, for the 32 bytes of h and the encoding of S. Every input is public, so the products and the pairings may take variable time.
	// For P = [h1]P2 + Ppub-s and g = e(P1, Ppub-s), bilinearity makes w' = e(S', P)·g^h' = e([h1]S', P2)·e(S' + [h']P1, Ppub-s), whose pairings take the lines of P2, which every key shares, and those of Ppub-s, which the instance keeps, and share their squares and one final exponentiation. [h1]S' is not the point at infinity, as h1 lies in [1, N − 1]; S' + [h']P1 may be, and its pairing is then 1. Both stay projective, as the factors of the lines take one inversion for both. For an ID that has no key, P is the point at infinity, e(S', P) = 1 and w' = g^h', so the signature verifies just if h' = H2(M' ‖ g^h', N), which nothing finds but by chance.
	[SkipLocalsInit]
	private bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> h, ReadOnlySpan<byte> s, ReadOnlySpan<byte> id)
	{
		// B1: h' in [1, N − 1]; B2: S' on the curve, which has cofactor 1, so in G1.
		if (!FieldElement<SM9Order>.TryImportNonzero(h, out FieldElement<SM9Order> hash) || !SM9G1.TryDecode(s, out SM9AffinePoint<SM9Fp> point))
		{
			return false;
		}

		// B3 to B8: w' = e([h1]S', P2)·e(S' + [h']P1, Ppub-s) for h1 = H1(ID ‖ hid, N).
		SM9Hash.H1(id, _hid, out FieldElement<SM9Order> h1);
		SM9G1.MultiplyVariableTime(in point, in h1, out SM9Point<SM9Fp> product);
		SM9G1.MultiplyBaseAddVariableTime(in hash, in point, out SM9Point<SM9Fp> sum);
		SM9PairingLines.Generator.PairVariableTime(in product, GetLines(), in sum, out SM9Fp12 w);

		Span<byte> encoded = stackalloc byte[SM9GT.EncodedLength];
		SM9GT.Encode(in w, encoded);

		// B9: H2(M' ‖ w', N) = h'.
		SM9Hash.StartH2(message, out SM3KdfState state);
		state.Append(encoded);
		SM9Hash.Finish(in state, out FieldElement<SM9Order> expected);
		FieldElement<SM9Order>.Subtract(in expected, in hash, out expected);
		return FieldElement<SM9Order>.IsZero(in expected) is not 0;
	}

	private SM9PairingLines GetLines()
	{
		return _lines ?? PublishLines();
	}

	// Threads that verify at once may each build the lines, which are public, but only the first to finish publishes them.
	private SM9PairingLines PublishLines()
	{
		SM9PairingLines lines = new(in _publicKey);
		return Interlocked.CompareExchange(ref _lines, lines, null) ?? lines;
	}

	// Ppub-s = [ks]P2. Neither the time nor the addresses depend on ks.
	private void SetPrivateKey(in FieldElement<SM9Order> privateKey)
	{
		_privateKey = privateKey;
		SM9G2.MultiplyBase(in privateKey, out _publicKey);
		_hasPrivateKey = true;
	}

	private void ThrowIfNoPrivateKey()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (!_hasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("master private key");
		}
	}
}
