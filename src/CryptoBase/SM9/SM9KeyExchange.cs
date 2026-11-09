using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.Kdf;

namespace CryptoBase.SM9;

/// <summary>
/// Provides one party of the SM9 key exchange protocol (GB/T 38635.2-2020, GM/T 0044.3-2016, Sec. 6.1).
/// </summary>
/// <remarks>
/// <para>
/// Both parties hold key exchange keys of their IDs under one encryption master key and one identifier hid, and each needs the ID of the other before the exchange starts. An instance draws an ephemeral key for the ID of its peer when it is created. The initiator sends its ephemeral public key R_A to the responder, and the responder sends R_B back; each party then derives the shared key from the ephemeral public key of its peer.
/// Both parties derive the same key of the length they choose.
/// </para>
/// <para>
/// The key confirmation of the protocol is optional. A derivation gives the value that the party sends, S_B of the responder or S_A of the initiator, and the value it expects from its peer. The responder sends S_B with R_B, and the initiator sends S_A once it has checked S_B; compare each received value with the expected one.
/// </para>
/// <para>
/// The key exchange key must not be disposed before the instance derives. An instance derives once: a successful derivation erases its secrets, and a later one throws <see cref="InvalidOperationException" />; a derivation that fails on the input of the peer leaves the instance as it was. An instance is not thread-safe. Disposal erases the secrets and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM9KeyExchange : IDisposable
{
	private const int PointLength = 2 * SM9Fp.ByteLength;

	private readonly SM9KeyExchangeRole _role;
	private readonly SM9KeyExchangeKey _key;
	private readonly byte[] _peerId;
	// x ‖ y of the ephemeral public key R.
	private InlineArray64<byte> _ephemeralPublicKey;
	// The ephemeral private key r, plain.
	private FieldElement<SM9Order> _secret;
	// g^r for g = e(Ppub-e, P2): g1' of the initiator or g2 of the responder.
	private SM9Fp12 _power;
	private bool _derived;
	private bool _disposed;

	private SM9KeyExchange(SM9KeyExchangeRole role, SM9KeyExchangeKey key, byte[] peerId)
	{
		_role = role;
		_key = key;
		_peerId = peerId;
	}

	/// <summary>
	/// Gets the length of an ephemeral public key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int EphemeralPublicKeyLength => SM9G1.EncodedLength;

	/// <summary>
	/// Gets the length of a confirmation value, in bytes.
	/// </summary>
	public static int ConfirmationLength => SM9Encryption.HashLength;

	/// <summary>
	/// Starts the key exchange for one party with a new random ephemeral key.
	/// </summary>
	/// <param name="key">The key exchange key of the party, which must not be disposed before the instance derives.</param>
	/// <param name="peerId">The ID of the peer, whose key exchange key is of the same master key and hid.</param>
	/// <param name="role">The role of the party.</param>
	/// <returns>An instance that holds the ephemeral key.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="role" /> is not a defined value.</exception>
	/// <exception cref="CryptographicException">No key exists for <paramref name="peerId" /> under the master key and the hid of <paramref name="key" />.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="key" /> has been disposed.</exception>
	public static SM9KeyExchange Create(SM9KeyExchangeKey key, ReadOnlySpan<byte> peerId, SM9KeyExchangeRole role)
	{
		return Create(key, peerId, role, SystemRandom.Fill);
	}

	/// <summary>
	/// Writes the ephemeral public key of the party, R_A of the initiator or R_B of the responder.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="EphemeralPublicKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportEphemeralPublicKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EphemeralPublicKeyLength, nameof(destination));

		destination[0] = 0x04;
		((ReadOnlySpan<byte>)_ephemeralPublicKey).CopyTo(destination.Slice(1));
		return EphemeralPublicKeyLength;
	}

	/// <summary>
	/// Derives the shared key from the ephemeral public key of the peer, without key confirmation.
	/// </summary>
	/// <remarks>As <see cref="TryDeriveKey(ReadOnlySpan{byte}, Span{byte}, Span{byte}, Span{byte})" />.</remarks>
	/// <param name="peerEphemeralPublicKey">The ephemeral public key of the peer.</param>
	/// <param name="sharedKey">The buffer that receives the shared key; its length is that of the key.</param>
	/// <returns><see langword="true" /> if the key was derived; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="sharedKey" /> is empty.</exception>
	/// <exception cref="InvalidOperationException">The instance has derived a key already.</exception>
	/// <exception cref="ObjectDisposedException">The instance or its key exchange key has been disposed.</exception>
	public bool TryDeriveKey(ReadOnlySpan<byte> peerEphemeralPublicKey, Span<byte> sharedKey)
	{
		ThrowIfCannotDerive(sharedKey);
		return Derive(peerEphemeralPublicKey, sharedKey, default, default);
	}

	/// <summary>
	/// Derives the shared key and the confirmation values from the ephemeral public key of the peer.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The method returns <see langword="false" /> if <paramref name="peerEphemeralPublicKey" /> is not a point on the curve in the uncompressed encoding; the outputs then remain unchanged. They also remain unchanged if the method throws.
	/// </para>
	/// <para>
	/// The responder sends <paramref name="confirmation" />, S_B, with its ephemeral public key and expects <paramref name="peerConfirmation" />, S_2, to equal S_A of the initiator. The initiator sends <paramref name="confirmation" />, S_A, and expects <paramref name="peerConfirmation" />, S_1, to equal S_B of the responder.
	/// </para>
	/// <para>
	/// The input may overlap the outputs, but the outputs must not overlap one another.
	/// </para>
	/// </remarks>
	/// <param name="peerEphemeralPublicKey">The ephemeral public key of the peer.</param>
	/// <param name="sharedKey">The buffer that receives the shared key; its length is that of the key.</param>
	/// <param name="confirmation">The buffer that receives the confirmation value that the party sends, at least <see cref="ConfirmationLength" /> bytes long.</param>
	/// <param name="peerConfirmation">The buffer that receives the confirmation value that the party expects from its peer, at least <see cref="ConfirmationLength" /> bytes long.</param>
	/// <returns><see langword="true" /> if the key was derived; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="sharedKey" /> is empty, <paramref name="confirmation" /> or <paramref name="peerConfirmation" /> is too short, or the outputs overlap.</exception>
	/// <exception cref="InvalidOperationException">The instance has derived a key already.</exception>
	/// <exception cref="ObjectDisposedException">The instance or its key exchange key has been disposed.</exception>
	public bool TryDeriveKey(ReadOnlySpan<byte> peerEphemeralPublicKey, Span<byte> sharedKey, Span<byte> confirmation, Span<byte> peerConfirmation)
	{
		ThrowIfCannotDerive(sharedKey);
		SM3KeyConfirmation.CheckOutputs(sharedKey, ref confirmation, ref peerConfirmation, ConfirmationLength);
		return Derive(peerEphemeralPublicKey, sharedKey, confirmation, peerConfirmation);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_secret.ZeroMemory();
		_power.ZeroMemory();
		_derived = true;
		_disposed = true;
	}

	// Create with the randomness of fill, which draws the ephemeral key r in [1, N − 1] (GM/T 0044.3-2016, Sec. 6.1, A2 and B2).
	internal static SM9KeyExchange Create(SM9KeyExchangeKey key, ReadOnlySpan<byte> peerId, SM9KeyExchangeRole role, Action<Span<byte>> fill)
	{
		ArgumentNullException.ThrowIfNull(key);

		if (role is not (SM9KeyExchangeRole.Initiator or SM9KeyExchangeRole.Responder))
		{
			throw new ArgumentOutOfRangeException(nameof(role), role, null);
		}

		SM9GTBase g = key.GetBase();

		// A1 or B1: h1 = H1(ID ‖ hid, N) for the ID of the peer, whose user public key is Q = [h1]P1 + Ppub-e.
		SM9Hash.H1(peerId, key.Hid, out FieldElement<SM9Order> h1);
		SM9KeyExchange exchange = new(role, key, peerId.ToArray());
		exchange.Start(key.MasterPublicKey, in h1, g, fill);
		return exchange;
	}

	// A3 or B3: R = [r]Q = [r·h1]P1 + [r]Ppub-e by SM9Encryption.MultiplyUserKey, which r in [1, N − 1] keeps from the point at infinity unless Q is, for an ID that has no key, which throws with r erased, and g^r, of A5 or B4. Neither the time nor the addresses depend on r.
	[SkipLocalsInit]
	private void Start(SM9G1FixedBase masterPublicKey, in FieldElement<SM9Order> h1, SM9GTBase g, Action<Span<byte>> fill)
	{
		Span<byte> encoded = stackalloc byte[SM9G1.EncodedLength];
		FieldElement<SM9Order>.ToMontgomery(in h1, out FieldElement<SM9Order> factor);
		Unsafe.SkipInit(out FieldElement<SM9Order> product);
		SM9Kgc.GenerateScalar(fill, out _secret);

		try
		{
			SM9Encryption.MultiplyUserKey(masterPublicKey, in factor, in _secret, out product, encoded);
		}
		catch
		{
			_secret.ZeroMemory();
			throw;
		}
		finally
		{
			product.ZeroMemory();
		}

		encoded.Slice(1).CopyTo(_ephemeralPublicKey);
		g.Power(in _secret, out _power);
	}

	// A5 to A8 for the initiator, B4 to B6 and B8 for the responder.
	[SkipLocalsInit]
	private bool Derive(ReadOnlySpan<byte> peerEphemeralPublicKey, Span<byte> sharedKey, Span<byte> confirmation, Span<byte> peerConfirmation)
	{
		SM9G2PrivateKey privateKey = _key.GetKey();

		// A5 or B4: R of the peer lies on the curve, which has cofactor 1, so in G1; the point at infinity has no uncompressed encoding.
		if (!SM9G1.TryDecode(peerEphemeralPublicKey, out SM9AffinePoint<SM9Fp> point))
		{
			return false;
		}

		// R of the peer is read again for the hashes, which may come after an output that overlaps it.
		Span<byte> peerEphemeral = stackalloc byte[PointLength];
		peerEphemeralPublicKey.Slice(1).CopyTo(peerEphemeral);
		using CryptoBuffer<byte> powers = new(stackalloc byte[3 * SM9GT.EncodedLength]);
		using CryptoBuffer<byte> inner = new(stackalloc byte[ConfirmationLength]);
		Unsafe.SkipInit(out SM9Fp12 pairing);
		Unsafe.SkipInit(out SM9Fp12 cube);
		Unsafe.SkipInit(out SM3KdfState kdf);
		Unsafe.SkipInit(out SM3Core hash);

		try
		{
			// e(R, de) for R of the peer, g2' = e(RB, deA) of the initiator or g1 = e(RA, deB) of the responder, and g3 = e(R, de)^r.
			privateKey.PairVariableTime(in point, out pairing);
			SM9GT.Power(in pairing, in _secret, out cube);
			bool initiator = _role is SM9KeyExchangeRole.Initiator;
			ref readonly SM9Fp12 first = ref initiator ? ref _power : ref pairing;
			ref readonly SM9Fp12 second = ref initiator ? ref pairing : ref _power;
			Span<byte> g1 = powers.Span.Slice(0, SM9GT.EncodedLength);
			SM9GT.Encode(in first, g1);
			SM9GT.Encode(in second, powers.Span.Slice(SM9GT.EncodedLength, SM9GT.EncodedLength));
			SM9GT.Encode(in cube, powers.Span.Slice(2 * SM9GT.EncodedLength));
			ReadOnlySpan<byte> ownEphemeral = _ephemeralPublicKey;
			ReadOnlySpan<byte> ephemeralA = initiator ? ownEphemeral : peerEphemeral;
			ReadOnlySpan<byte> ephemeralB = initiator ? peerEphemeral : ownEphemeral;
			ReadOnlySpan<byte> idA = initiator ? _key.Id : _peerId;
			ReadOnlySpan<byte> idB = initiator ? _peerId : _key.Id;

			if (!confirmation.IsEmpty)
			{
				// Hv(g2 ‖ g3 ‖ ID_A ‖ ID_B ‖ R_A ‖ R_B).
				hash = HashCore.Create<SM3Core>();
				HashCore.Append(ref hash, powers.Span.Slice(SM9GT.EncodedLength));
				HashCore.Append(ref hash, idA);
				HashCore.Append(ref hash, idB);
				HashCore.Append(ref hash, ephemeralA);
				HashCore.Append(ref hash, ephemeralB);
				HashCore.Finalize(ref hash, inner.Span);
				// S_B and S_1 take 0x82, S_A and S_2 take 0x83.
				SM3KeyConfirmation.Compute(initiator ? (byte)0x83 : (byte)0x82, g1, inner.Span, confirmation);
				SM3KeyConfirmation.Compute(initiator ? (byte)0x82 : (byte)0x83, g1, inner.Span, peerConfirmation);
			}

			// A7 or B5: SK = KDF(ID_A ‖ ID_B ‖ R_A ‖ R_B ‖ g1 ‖ g2 ‖ g3, klen).
			kdf.Initialize();
			kdf.Append(idA);
			kdf.Append(idB);
			kdf.Append(ephemeralA);
			kdf.Append(ephemeralB);
			kdf.Append(powers.Span);
			kdf.Derive(sharedKey);
		}
		finally
		{
			kdf.Clear();
			hash.ZeroMemory();
			pairing.ZeroMemory();
			cube.ZeroMemory();
		}

		_secret.ZeroMemory();
		_power.ZeroMemory();
		_derived = true;
		return true;
	}

	private void ThrowIfCannotDerive(Span<byte> sharedKey)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfZero(sharedKey.Length, nameof(sharedKey));

		if (_derived)
		{
			throw new InvalidOperationException("The instance has derived a key already.");
		}
	}
}
