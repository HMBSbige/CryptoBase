using CryptoBase.EllipticCurves;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.Kdf;

namespace CryptoBase.SM2;

/// <summary>
/// Provides one party of the SM2 key exchange protocol (GB/T 32918.3-2016, Sec. 6.1) over the recommended curve.
/// </summary>
/// <remarks>
/// <para>
/// An instance draws an ephemeral key when it is created. The initiator sends its ephemeral public key to the responder, and the responder sends its own back; each party then derives the shared key from the static public key, the ID and the ephemeral public key of its peer.
/// Both parties derive the same key, of the length they choose.
/// </para>
/// <para>
/// The key confirmation of the protocol is optional. A derivation gives the value that the party sends, S_B of the responder or S_A of the initiator, and the value it expects from its peer. The responder sends S_B with its ephemeral public key, and the initiator sends S_A once it has checked S_B; compare each received value with the expected one.
/// </para>
/// <para>
/// An instance derives once: after a successful derivation, a later one throws <see cref="InvalidOperationException" />; a derivation that fails on the inputs of the peer leaves the instance as it was. An instance is not thread-safe. Disposal erases the key material and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM2KeyExchange : IDisposable
{
	private const int CoordinateLength = 32;

	private readonly SM2KeyExchangeRole _role;
	// x ‖ y of the ephemeral public key.
	private InlineArray64<byte> _ephemeralPublicKey;
	private InlineArray32<byte> _z;
	// (d + x̄·r) mod n, plain.
	private FieldElement<SM2Order> _secret;
	private bool _derived;
	private bool _disposed;

	private SM2KeyExchange(SM2KeyExchangeRole role)
	{
		_role = role;
	}

	/// <summary>
	/// Gets the length of an ephemeral public key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int EphemeralPublicKeyLength => SM2KeyState.PublicKeyLength;

	/// <summary>
	/// Gets the length of a confirmation value, in bytes.
	/// </summary>
	public static int ConfirmationLength => SM2KeyState.HashLength;

	/// <summary>
	/// Starts the key exchange for one party with a new random ephemeral key.
	/// </summary>
	/// <remarks><paramref name="key" /> may be disposed once the method returns.</remarks>
	/// <param name="key">The static key of the party, which must hold the private key.</param>
	/// <param name="id">The ID of the party, at most <see cref="SM2Key.MaxIdLength" /> bytes long, such as <see cref="SM2Key.DefaultId" />; the peer needs the same ID.</param>
	/// <param name="role">The role of the party.</param>
	/// <returns>An instance that holds the ephemeral key.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="id" /> is too long, or <paramref name="role" /> is not a defined value.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="key" /> does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="key" /> has been disposed.</exception>
	public static SM2KeyExchange Create(SM2Key key, ReadOnlySpan<byte> id, SM2KeyExchangeRole role)
	{
		return Create(key, id, role, SystemRandom.Fill);
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
	/// Derives the shared key from the inputs of the peer, without key confirmation.
	/// </summary>
	/// <remarks>As <see cref="TryDeriveKey(SM2Key, ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte}, Span{byte}, Span{byte})" />.</remarks>
	/// <param name="peerKey">The static public key of the peer.</param>
	/// <param name="peerId">The ID of the peer, at most <see cref="SM2Key.MaxIdLength" /> bytes long.</param>
	/// <param name="peerEphemeralPublicKey">The ephemeral public key of the peer.</param>
	/// <param name="sharedKey">The buffer that receives the shared key; its length is that of the key.</param>
	/// <returns><see langword="true" /> if the key was derived; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="peerKey" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="peerId" /> is too long, or <paramref name="sharedKey" /> is empty.</exception>
	/// <exception cref="InvalidOperationException">The instance has derived a key already.</exception>
	/// <exception cref="ObjectDisposedException">The instance or <paramref name="peerKey" /> has been disposed.</exception>
	public bool TryDeriveKey(SM2Key peerKey, ReadOnlySpan<byte> peerId, ReadOnlySpan<byte> peerEphemeralPublicKey, Span<byte> sharedKey)
	{
		ThrowIfCannotDerive(peerKey, peerId, sharedKey);
		return Derive(peerKey, peerId, peerEphemeralPublicKey, sharedKey, default, default);
	}

	/// <summary>
	/// Derives the shared key and the confirmation values from the inputs of the peer.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The method returns <see langword="false" /> if <paramref name="peerEphemeralPublicKey" /> is not a point on the curve in the uncompressed encoding, or the shared point is the point at infinity; the outputs then remain unchanged. They also remain unchanged if the method throws.
	/// </para>
	/// <para>
	/// The responder sends <paramref name="confirmation" />, S_B, with its ephemeral public key and expects <paramref name="peerConfirmation" />, S_2, to equal S_A of the initiator. The initiator sends <paramref name="confirmation" />, S_A, and expects <paramref name="peerConfirmation" />, S_1, to equal S_B of the responder.
	/// </para>
	/// <para>
	/// The inputs may overlap the outputs, but the outputs must not overlap one another.
	/// </para>
	/// </remarks>
	/// <param name="peerKey">The static public key of the peer.</param>
	/// <param name="peerId">The ID of the peer, at most <see cref="SM2Key.MaxIdLength" /> bytes long.</param>
	/// <param name="peerEphemeralPublicKey">The ephemeral public key of the peer.</param>
	/// <param name="sharedKey">The buffer that receives the shared key; its length is that of the key.</param>
	/// <param name="confirmation">The buffer that receives the confirmation value that the party sends, at least <see cref="ConfirmationLength" /> bytes long.</param>
	/// <param name="peerConfirmation">The buffer that receives the confirmation value that the party expects from its peer, at least <see cref="ConfirmationLength" /> bytes long.</param>
	/// <returns><see langword="true" /> if the key was derived; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="peerKey" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="peerId" /> is too long, <paramref name="sharedKey" /> is empty, <paramref name="confirmation" /> or <paramref name="peerConfirmation" /> is too short, or the outputs overlap.</exception>
	/// <exception cref="InvalidOperationException">The instance has derived a key already.</exception>
	/// <exception cref="ObjectDisposedException">The instance or <paramref name="peerKey" /> has been disposed.</exception>
	public bool TryDeriveKey(SM2Key peerKey, ReadOnlySpan<byte> peerId, ReadOnlySpan<byte> peerEphemeralPublicKey, Span<byte> sharedKey, Span<byte> confirmation, Span<byte> peerConfirmation)
	{
		ThrowIfCannotDerive(peerKey, peerId, sharedKey);
		ArgumentOutOfRangeException.ThrowIfLessThan(confirmation.Length, ConfirmationLength, nameof(confirmation));
		ArgumentOutOfRangeException.ThrowIfLessThan(peerConfirmation.Length, ConfirmationLength, nameof(peerConfirmation));

		confirmation = confirmation.Slice(0, ConfirmationLength);
		peerConfirmation = peerConfirmation.Slice(0, ConfirmationLength);

		if (sharedKey.Overlaps(confirmation) || sharedKey.Overlaps(peerConfirmation) || confirmation.Overlaps(peerConfirmation))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedKey));
		}

		return Derive(peerKey, peerId, peerEphemeralPublicKey, sharedKey, confirmation, peerConfirmation);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_secret.ZeroMemory();
		_derived = true;
		_disposed = true;
	}

	// Create with the randomness of fill, which draws the ephemeral key r in [1, n − 1] (GB/T 32918.3-2016, Sec. 6.1, A1 and B1).
	internal static SM2KeyExchange Create(SM2Key key, ReadOnlySpan<byte> id, SM2KeyExchangeRole role, Action<Span<byte>> fill)
	{
		ArgumentNullException.ThrowIfNull(key);
		ref SM2KeyState state = ref key.GetState();
		SM2KeyState.ThrowIfInvalidId(id, nameof(id));

		if (role is not (SM2KeyExchangeRole.Initiator or SM2KeyExchangeRole.Responder))
		{
			throw new ArgumentOutOfRangeException(nameof(role), role, null);
		}

		if (!state.HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		SM2KeyExchange exchange = new(role);
		state.ComputeZ(id, exchange._z);
		exchange.Start(in state.Key.PrivateScalar, fill);
		return exchange;
	}

	// R = r·G and t = (d + x̄·r) mod n (A2, A4 and A5, or B2 to B4), which takes the place of d and r from here on. Neither the time nor the addresses depend on d or r.
	[SkipLocalsInit]
	private void Start(in FieldElement<SM2Order> privateKey, Action<Span<byte>> fill)
	{
		Unsafe.SkipInit(out FieldElement<SM2Order> ephemeral);
		Unsafe.SkipInit(out FieldElement<SM2Order> product);
		Span<byte> encoded = stackalloc byte[EphemeralPublicKeyLength];

		try
		{
			ECKey<SM2Curve, SM2CurveField, SM2Order>.GeneratePrivateScalar(fill, out ephemeral);
			ECGroup<SM2Curve, SM2CurveField, SM2Order>.MultiplyBaseToAffine(in ephemeral, out AffinePoint<SM2CurveField> point);
			ECGroup<SM2Curve, SM2CurveField, SM2Order>.Encode(in point, encoded);
			encoded.Slice(1).CopyTo(_ephemeralPublicKey);
			// x̄·R times a plain r is the plain x̄·r.
			Truncate(encoded.Slice(1, CoordinateLength), out FieldElement<SM2Order> truncated);
			FieldElement<SM2Order>.ToMontgomery(in truncated, out truncated);
			FieldElement<SM2Order>.Multiply(in truncated, in ephemeral, out product);
			FieldElement<SM2Order>.Add(in privateKey, in product, out _secret);
		}
		finally
		{
			ephemeral.ZeroMemory();
			product.ZeroMemory();
		}
	}

	// A6 to A10 for the initiator, B5 to B8 and B10 for the responder.
	[SkipLocalsInit]
	private bool Derive(SM2Key peerKey, ReadOnlySpan<byte> peerId, ReadOnlySpan<byte> peerEphemeralPublicKey, Span<byte> sharedKey, Span<byte> confirmation, Span<byte> peerConfirmation)
	{
		// The peer's ephemeral key is read again for the confirmation values, which may come after an output that overlaps it.
		Span<byte> peerEphemeral = stackalloc byte[EphemeralPublicKeyLength];

		// A6 or B5: R of the peer lies on the curve; it is not the point at infinity, which has no uncompressed encoding.
		if (peerEphemeralPublicKey.Length != EphemeralPublicKeyLength || !ECGroup<SM2Curve, SM2CurveField, SM2Order>.TryDecode(peerEphemeralPublicKey, out AffinePoint<SM2CurveField> ephemeralPoint))
		{
			return false;
		}

		peerEphemeralPublicKey.CopyTo(peerEphemeral);
		ref SM2KeyState peer = ref peerKey.GetState();
		using CryptoBuffer<byte> shared = new(stackalloc byte[EphemeralPublicKeyLength]);

		// A7 or B6: U = t·(P + x̄·R) with h = 1, not the point at infinity.
		if (!TryMultiplyShared(ref peer, peerEphemeral.Slice(1, CoordinateLength), in ephemeralPoint, shared.Span))
		{
			return false;
		}

		Span<byte> peerZ = stackalloc byte[SM2KeyState.HashLength];
		peer.ComputeZ(peerId, peerZ);
		bool initiator = _role is SM2KeyExchangeRole.Initiator;
		ReadOnlySpan<byte> ownZ = _z;
		ReadOnlySpan<byte> zA = initiator ? ownZ : peerZ;
		ReadOnlySpan<byte> zB = initiator ? peerZ : ownZ;
		ReadOnlySpan<byte> x = shared.Span.Slice(1, CoordinateLength);
		ReadOnlySpan<byte> y = shared.Span.Slice(1 + CoordinateLength, CoordinateLength);
		Unsafe.SkipInit(out SM3KdfState kdf);
		Unsafe.SkipInit(out SM3Core hash);
		using CryptoBuffer<byte> inner = new(stackalloc byte[SM2KeyState.HashLength]);

		try
		{
			if (!confirmation.IsEmpty)
			{
				// SM3(x ‖ Z_A ‖ Z_B ‖ x1 ‖ y1 ‖ x2 ‖ y2), with (x1, y1) of the initiator and (x2, y2) of the responder.
				ReadOnlySpan<byte> ownEphemeral = _ephemeralPublicKey;
				ReadOnlySpan<byte> peerCoordinates = peerEphemeral.Slice(1);
				hash = HashCore.Create<SM3Core>();
				HashCore.Append(ref hash, x);
				HashCore.Append(ref hash, zA);
				HashCore.Append(ref hash, zB);
				HashCore.Append(ref hash, initiator ? ownEphemeral : peerCoordinates);
				HashCore.Append(ref hash, initiator ? peerCoordinates : ownEphemeral);
				HashCore.Finalize(ref hash, inner.Span);
				// S_B and S_1 take 0x02, S_A and S_2 take 0x03.
				Confirm(initiator ? (byte)0x03 : (byte)0x02, y, inner.Span, confirmation);
				Confirm(initiator ? (byte)0x02 : (byte)0x03, y, inner.Span, peerConfirmation);
			}

			// A8 or B7: K = KDF(x ‖ y ‖ Z_A ‖ Z_B, klen).
			kdf.Initialize();
			kdf.Append(shared.Span.Slice(1));
			kdf.Append(zA);
			kdf.Append(zB);
			kdf.Derive(sharedKey);
		}
		finally
		{
			kdf.Clear();
			hash.ZeroMemory();
		}

		_secret.ZeroMemory();
		_derived = true;
		return true;
	}

	// Writes the encoding of U = t·(P + x̄·R) for the static key P and the ephemeral key R of the peer, and x the x-coordinate of R; false if U is the point at infinity. With the windows of P, or with kernels for k·P + l·Q, U = t·P + (t·x̄)·R in fixed time. Without either, P + x̄·R comes from public inputs alone, in variable time, before t·(P + x̄·R) in fixed time. Not inlined, so that the frame of Derive keeps the size it has without the windows.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	private bool TryMultiplyShared(ref SM2KeyState peer, ReadOnlySpan<byte> x, in AffinePoint<SM2CurveField> ephemeral, Span<byte> shared)
	{
		ECPointTable<SM2Curve, SM2CurveField, SM2Order>? table = peer.GetExchangeTable();

		if (table is null && !ECGroup<SM2Curve, SM2CurveField, SM2Order>.HasMultiplyAdd)
		{
			return TryAddMultiple(in peer.Key.PublicPoint, x, in ephemeral, out AffinePoint<SM2CurveField> sum) && ECGroup<SM2Curve, SM2CurveField, SM2Order>.TryMultiplyEncode(in sum, in _secret, shared);
		}

		Unsafe.SkipInit(out FieldElement<SM2Order> product);

		try
		{
			// x̄·R times a plain t is the plain t·x̄.
			Truncate(x, out FieldElement<SM2Order> truncated);
			FieldElement<SM2Order>.ToMontgomery(in truncated, out truncated);
			FieldElement<SM2Order>.Multiply(in truncated, in _secret, out product);

			if (table is null)
			{
				return ECGroup<SM2Curve, SM2CurveField, SM2Order>.TryMultiplyAddEncode(in peer.Key.PublicPoint, in _secret, in ephemeral, in product, shared);
			}

			return ECGroup<SM2Curve, SM2CurveField, SM2Order>.TryMultiplyAddEncode(table, in _secret, in ephemeral, in product, shared);
		}
		finally
		{
			product.ZeroMemory();
		}
	}

	// SM3(tag ‖ y ‖ inner).
	[SkipLocalsInit]
	private static void Confirm(byte tag, ReadOnlySpan<byte> y, ReadOnlySpan<byte> inner, Span<byte> destination)
	{
		SM3Core hash = HashCore.Create<SM3Core>();
		HashCore.Append(ref hash, new ReadOnlySpan<byte>(in tag));
		HashCore.Append(ref hash, y);
		HashCore.Append(ref hash, inner);
		HashCore.Finalize(ref hash, destination);
		hash.ZeroMemory();
	}

	// x̄ = 2^w + (x mod 2^w) for w = 127, from the 32 big-endian bytes of x (GB/T 32918.3-2016, Sec. 6.1, A4).
	private static void Truncate(ReadOnlySpan<byte> x, out FieldElement<SM2Order> result)
	{
		Unsafe.SkipInit(out result);
		Span<ulong> limbs = MemoryMarshal.Cast<FieldElement<SM2Order>, ulong>(new Span<FieldElement<SM2Order>>(ref result));
		limbs[0] = BinaryPrimitives.ReadUInt64BigEndian(x.Slice(24));
		limbs[1] = BinaryPrimitives.ReadUInt64BigEndian(x.Slice(16)) | 1UL << 63;
		limbs[2] = 0;
		limbs[3] = 0;
	}

	// sum = P + x̄·R for the static public key P and the ephemeral public key R of the peer, both on the curve, and x the x-coordinate of R; false if that is the point at infinity. Every input is public, so the time may depend on them.
	[SkipLocalsInit]
	private static bool TryAddMultiple(in AffinePoint<SM2CurveField> point, ReadOnlySpan<byte> x, in AffinePoint<SM2CurveField> ephemeral, out AffinePoint<SM2CurveField> sum)
	{
		Truncate(x, out FieldElement<SM2Order> truncated);
		FieldElement<SM2Order> zero = default;
		ECVariableTimeGroup<SM2Curve, SM2CurveField, SM2Order>.MultiplyAdd(in zero, in ephemeral, in truncated, out JacobianPoint<SM2CurveField> product);
		ECVariableTimeGroup<SM2Curve, SM2CurveField, SM2Order>.Add(in product, in point, out product);

		if (product.IsInfinity)
		{
			sum = default;
			return false;
		}

		Unsafe.SkipInit(out sum);
		ECGroup<SM2Curve, SM2CurveField, SM2Order>.ToAffineVariableTime(new ReadOnlySpan<JacobianPoint<SM2CurveField>>(in product), new Span<AffinePoint<SM2CurveField>>(ref sum));
		return true;
	}

	private void ThrowIfCannotDerive(SM2Key peerKey, ReadOnlySpan<byte> peerId, Span<byte> sharedKey)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentNullException.ThrowIfNull(peerKey);
		_ = peerKey.GetState();
		SM2KeyState.ThrowIfInvalidId(peerId, nameof(peerId));
		ArgumentOutOfRangeException.ThrowIfZero(sharedKey.Length, nameof(sharedKey));

		if (_derived)
		{
			throw new InvalidOperationException("The instance has derived a key already.");
		}
	}
}
