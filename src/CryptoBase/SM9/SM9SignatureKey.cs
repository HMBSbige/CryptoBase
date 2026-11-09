using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;
using CryptoBase.Signatures;

namespace CryptoBase.SM9;

/// <summary>
/// Provides the SM9 signing key of a user (GB/T 38635.2-2020, GM/T 0044-2016), which the key generation center extracts with <see cref="SM9SignatureMasterKey.ExtractKey" />.
/// </summary>
/// <remarks>
/// <para>
/// The private key dsA is a point of G1 in the uncompressed encoding, 0x04 ‖ x ‖ y, and the instance holds the master public key with it. A verifier needs the master public key with its identifier hid and the ID of the signer; see <see cref="SM9SignatureMasterKey.Verify(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})" />.
/// </para>
/// <para>
/// A signature is h ‖ S of GM/T 0044.2, 97 bytes with S uncompressed, or the SM9Signature of GB/T 41389-2022 (GM/T 0080-2020) in DER, 104 bytes. Signing is randomized: signing a message twice gives two different signatures.
/// </para>
/// <para>
/// Signing may run concurrently on one instance; to sign repeatedly, keep one instance. Disposal erases the private key and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM9SignatureKey : IDisposable
{
	internal const int HashLength = 32;

	private const int AdditionalDataLength = 32;

	// dsA, with the table of its products from the signatures that SM9G1FixedBase sets on.
	private readonly SM9G1FixedBase _privateKey;
	private readonly SM9AffinePoint<SM9Fp2> _masterPublicKey;
	// g = e(P1, Ppub-s), once an import or signature has computed it.
	private SM9GTBase? _base;
	private bool _disposed;

	internal SM9SignatureKey(in SM9AffinePoint<SM9Fp> privateKey, in SM9AffinePoint<SM9Fp2> masterPublicKey, SM9GTBase? gtBase)
	{
		_privateKey = new SM9G1FixedBase(in privateKey, true);
		_masterPublicKey = masterPublicKey;
		_base = gtBase;
	}

	/// <summary>
	/// Gets the length of the private key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PrivateKeyLength => SM9G1.EncodedLength;

	/// <summary>
	/// Gets the length of a signature h ‖ S, in bytes.
	/// </summary>
	public static int SignatureLength => HashLength + SM9G1.EncodedLength;

	/// <summary>
	/// Gets the length of a signature in DER, in bytes.
	/// </summary>
	public static int DerSignatureLength => SM9Der.SignatureLength;

	/// <summary>
	/// Imports the private key of a user.
	/// </summary>
	/// <remarks>
	/// The private key must lie on the curve and the master public key in G2, and the key must belong to <paramref name="id" /> and <paramref name="hid" /> under the master public key.
	/// </remarks>
	/// <param name="privateKey">The private key dsA in the uncompressed encoding, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <param name="masterPublicKey">The master public key Ppub-s in the uncompressed encoding, exactly <see cref="SM9SignatureMasterKey.PublicKeyLength" /> bytes long.</param>
	/// <param name="id">The ID of the user.</param>
	/// <param name="hid">The identifier hid of the generating function of the signing keys of the master key; 0x01 by default.</param>
	/// <returns>An instance that holds the private key and the master public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="privateKey" /> or <paramref name="masterPublicKey" /> has the wrong length or is not a valid point, or the private key is not that of <paramref name="id" /> and <paramref name="hid" /> under <paramref name="masterPublicKey" />.</exception>
	[SkipLocalsInit]
	public static SM9SignatureKey ImportPrivateKey(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> masterPublicKey, ReadOnlySpan<byte> id, byte hid = SM9Kgc.SignatureHid)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(privateKey.Length, PrivateKeyLength, nameof(privateKey));
		ArgumentOutOfRangeException.ThrowIfNotEqual(masterPublicKey.Length, SM9SignatureMasterKey.PublicKeyLength, nameof(masterPublicKey));

		if (!SM9G2.TryDecode(masterPublicKey, out SM9AffinePoint<SM9Fp2> publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(masterPublicKey));
		}

		Unsafe.SkipInit(out SM9AffinePoint<SM9Fp> point);
		Unsafe.SkipInit(out SM9Fp12 u);

		try
		{
			if (!SM9G1.TryDecode(privateKey, out point))
			{
				ThrowHelper.ThrowInvalidKey(nameof(privateKey));
			}

			// dsA = [ks/(h1 + ks)]P1 just if e(dsA, [h1]P2 + Ppub-s) = e(P1, P2)^ks = g, for h1 = H1(ID ‖ hid, N); the sum is the point at infinity only for an ID that has no key.
			SM9Hash.H1(id, hid, out FieldElement<SM9Order> h1);
			SM9Pairing.Pair(in SM9G1.Generator, in publicKey, out SM9Fp12 g);

			if (!SM9G2.MultiplyBaseAddVariableTime(in h1, in publicKey, out SM9AffinePoint<SM9Fp2> sum))
			{
				ThrowHelper.ThrowInvalidKey(nameof(privateKey));
			}

			SM9Pairing.Pair(in point, in sum, out u);

			if (SM9GT.AreEqual(in u, in g) is 0)
			{
				ThrowHelper.ThrowInvalidKey(nameof(privateKey));
			}

			return new SM9SignatureKey(in point, in publicKey, new SM9GTBase(in g));
		}
		finally
		{
			point.ZeroMemory();
			u.ZeroMemory();
		}
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

		SM9G1.Encode(in _privateKey.Point, destination.Slice(0, PrivateKeyLength));
		return PrivateKeyLength;
	}

	/// <summary>
	/// Signs <paramref name="message" /> into h ‖ S (GB/T 38635.2-2020, GM/T 0044.2-2016, Sec. 6.1), with S uncompressed.
	/// </summary>
	/// <remarks><paramref name="message" /> may overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="message">The message.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="SignatureLength" /> bytes long.</param>
	/// <returns>The value of <see cref="SignatureLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Sign(ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SignatureLength, nameof(destination));

		return Sign(message, destination, false);
	}

	/// <summary>
	/// Signs <paramref name="message" /> into the DER of an SM9Signature (GB/T 41389-2022), which holds h and S (GB/T 38635.2-2020, GM/T 0044.2-2016, Sec. 6.1).
	/// </summary>
	/// <remarks><paramref name="message" /> may overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="message">The message.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="DerSignatureLength" /> bytes long.</param>
	/// <returns>The value of <see cref="DerSignatureLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int SignDer(ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, DerSignatureLength, nameof(destination));

		return Sign(message, destination, true);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_privateKey.Dispose();
		_base?.Dispose();
		_base = null;
		_disposed = true;
	}

	// As below, with fresh system randomness as the additional data.
	[SkipLocalsInit]
	private int Sign(ReadOnlySpan<byte> message, Span<byte> destination, bool der)
	{
		using CryptoBuffer<byte> additionalData = new(stackalloc byte[AdditionalDataLength]);
		SystemRandom.Fill(additionalData.Span);
		return Sign(message, additionalData.Span, destination, der);
	}

	// GB/T 38635.2-2020, Sec. 6.1, with r from the nonces of SM3Nonce over the x-coordinate of dsA, which with one more bit fixes dsA, SM3(0x02 ‖ M ‖ 00000001) mod N and additionalData, which empty makes deterministic. A1 to A4 hash 0x02 ‖ M once, for every r.
	[SkipLocalsInit]
	internal int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData, Span<byte> destination, bool der)
	{
		Debug.Assert(destination.Length >= (der ? DerSignatureLength : SignatureLength));

		SM9GTBase g = GetBase();
		Span<byte> hash = stackalloc byte[HashLength];
		Span<byte> signature = stackalloc byte[SignatureLength];
		using CryptoBuffer<byte> encodedKey = new(stackalloc byte[SM9Fp.ByteLength]);
		Unsafe.SkipInit(out SM3KdfState prefix);
		Unsafe.SkipInit(out SM3Nonce<SM9Order> nonce);
		Unsafe.SkipInit(out FieldElement<SM9Order> r);
		Unsafe.SkipInit(out SM9AffinePoint<SM9Fp> s);

		try
		{
			SM9Hash.StartH2(message, out prefix);
			prefix.WriteBlock(1, hash);
			FieldElement<SM9Order>.ImportReduced(hash, out FieldElement<SM9Order> e);
			FieldElement<SM9Order>.Export(in e, hash);
			SM9Fp.ExportPlain(in _privateKey.Point.X, encodedKey.Span);
			nonce.Initialize(encodedKey.Span, hash, additionalData);
			FieldElement<SM9Order> h;

			do
			{
				nonce.Next(out r);
			}
			while (!TrySign(in prefix, in r, g, out h, out s));

			// A7.
			FieldElement<SM9Order>.Export(in h, signature.Slice(0, HashLength));
			SM9G1.Encode(in s, signature.Slice(HashLength));

			if (der)
			{
				SM9Der.WriteSignature(signature.Slice(0, HashLength), signature.Slice(HashLength), destination);
				return DerSignatureLength;
			}

			signature.CopyTo(destination);
			return SignatureLength;
		}
		finally
		{
			prefix.Clear();
			nonce.Clear();
			r.ZeroMemory();
			s.ZeroMemory();
		}
	}

	// A3 to A6 for r in [1, N − 1] and the state of H2 after 0x02 ‖ M: w = g^r, h = H2(M ‖ w, N), l = (r − h) mod N and S = [l]dsA. Returns false, so that the caller draws the next r, if l = 0. Nothing branches on or indexes by r, w or l before the result.
	[SkipLocalsInit]
	internal bool TrySign(in SM3KdfState prefix, in FieldElement<SM9Order> r, SM9GTBase g, out FieldElement<SM9Order> h, out SM9AffinePoint<SM9Fp> s)
	{
		using CryptoBuffer<byte> encoded = new(stackalloc byte[SM9GT.EncodedLength]);
		Unsafe.SkipInit(out SM9Fp12 w);
		Unsafe.SkipInit(out FieldElement<SM9Order> l);
		// The state goes on from 0x02 ‖ M for each r, so each attempt takes a copy, which it erases.
		SM3KdfState state = prefix;

		try
		{
			g.Power(in r, out w);
			SM9GT.Encode(in w, encoded.Span);
			state.Append(encoded.Span);
			SM9Hash.Finish(in state, out h);
			FieldElement<SM9Order>.Subtract(in r, in h, out l);
			ulong rejected = FieldElement<SM9Order>.IsZero(in l);
			_privateKey.Multiply(in l, out s);
			return rejected is 0;
		}
		finally
		{
			state.Clear();
			w.ZeroMemory();
			l.ZeroMemory();
		}
	}

	internal SM9GTBase GetBase()
	{
		return _base ?? SM9GTBase.Publish(ref _base, in SM9G1.Generator, in _masterPublicKey);
	}
}
