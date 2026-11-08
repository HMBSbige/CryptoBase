using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.SM9;

/// <summary>
/// Provides an SM9 encryption master key (GB/T 38635.2-2020, GM/T 0044-2016): the extraction of the private keys of users by the key generation center, for decryption, key decapsulation and the key exchange, and the encryption and key encapsulation to their IDs.
/// </summary>
/// <remarks>
/// <para>
/// The master private key ke is big-endian and must lie in [1, N − 1]. The master public key Ppub-e = [ke]P1 is a point of G1 in the uncompressed encoding, 0x04 ‖ x ‖ y, and must lie on the curve.
/// An instance that holds only the master public key encrypts and encapsulates; extracting keys needs the master private key. Extraction, encryption and encapsulation may run concurrently on one instance.
/// </para>
/// <para>
/// Encryption takes the stream cipher of the KDF and writes C1 ‖ C3 ‖ C2 of GM/T 0044.4 with C1 as x ‖ y, 96 bytes longer than the plaintext, or the SM9Cipher of GB/T 41389-2022 (GM/T 0080-2020) in DER, with C1 uncompressed and EnType 0. The plaintext must not be empty. The variant with a block cipher is not supported.
/// An encapsulation is the point C in the uncompressed encoding; the encapsulated key may have any length but 0.
/// </para>
/// <para>
/// The keys that <see cref="ExtractKey" /> gives decrypt and decapsulate; those that <see cref="ExtractKeyExchangeKey" /> gives serve the key exchange. The key generation center chooses the identifier hid of the generating function of each and publishes it with the master public key.
/// The instance holds the hid of decryption, 0x03 by default as GB/T 41389-2022 gives it, and takes it for extraction, encryption and encapsulation, so a sender imports the master public key with the hid of the master key that extracted the key of the recipient.
/// <see cref="ExtractKeyExchangeKey" /> takes the hid of the key exchange for each key, 0x02 by default.
/// </para>
/// <para>
/// To encrypt many messages, keep one instance rather than import the key for each. Disposal erases the master private key and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class SM9EncryptionMasterKey : IDisposable
{
	// ke, plain.
	private FieldElement<SM9Order> _privateKey;
	// Ppub-e, with the table of its products from the encryptions and encapsulations that SM9G1FixedBase sets on.
	private readonly SM9G1FixedBase _publicKey;
	private bool _hasPrivateKey;
	private readonly byte _hid;
	// g = e(Ppub-e, P2), once an encryption or encapsulation has computed it.
	private SM9GTBase? _base;
	private bool _disposed;

	private SM9EncryptionMasterKey(in SM9AffinePoint<SM9Fp> publicKey, byte hid)
	{
		_publicKey = new SM9G1FixedBase(in publicKey, false);
		_hid = hid;
	}

	/// <summary>
	/// Gets the length of the master private key, in bytes.
	/// </summary>
	public static int PrivateKeyLength => SM9Kgc.PrivateKeyLength;

	/// <summary>
	/// Gets the length of the master public key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PublicKeyLength => SM9G1.EncodedLength;

	/// <summary>
	/// Gets the length of an encapsulation, the point C in the uncompressed encoding, in bytes.
	/// </summary>
	public static int EncapsulationLength => SM9G1.EncodedLength;

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
	/// Gets the identifier hid of the generating function of the private keys for decryption and key decapsulation, which extraction, encryption and encapsulation take.
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
	/// Gets the length of the ciphertext C1 ‖ C3 ‖ C2 that <see cref="Encrypt(ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte})" /> writes.
	/// </summary>
	/// <param name="plaintextLength">The length of the plaintext, in bytes.</param>
	/// <returns>The length of the ciphertext, in bytes, 96 bytes longer than the plaintext.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="plaintextLength" /> is not positive or gives a ciphertext longer than <see cref="int.MaxValue" />.</exception>
	public static int GetCiphertextLength(int plaintextLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(plaintextLength);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(plaintextLength, int.MaxValue - SM9Encryption.CiphertextOverhead);

		return SM9Encryption.CiphertextOverhead + plaintextLength;
	}

	/// <summary>
	/// Gets the length of the SM9Cipher that <see cref="EncryptDer(ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte})" /> writes.
	/// </summary>
	/// <param name="plaintextLength">The length of the plaintext, in bytes.</param>
	/// <returns>The length of the ciphertext, in bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="plaintextLength" /> is not positive or gives a ciphertext longer than <see cref="int.MaxValue" />.</exception>
	public static int GetDerCiphertextLength(int plaintextLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(plaintextLength);

		int length = SM9Der.GetCipherLength(plaintextLength);

		if (length < 0)
		{
			throw new ArgumentOutOfRangeException(nameof(plaintextLength), plaintextLength, "The ciphertext would be longer than int.MaxValue bytes.");
		}

		return length;
	}

	/// <summary>
	/// Generates a master key from a new random master private key.
	/// </summary>
	/// <param name="hid">The identifier hid of the generating function of the private keys for decryption and key decapsulation; 0x03 by default.</param>
	/// <returns>An instance that holds the master private key and the master public key.</returns>
	public static SM9EncryptionMasterKey GenerateKey(byte hid = SM9Kgc.EncryptionHid)
	{
		return GenerateKey(SystemRandom.Fill, hid);
	}

	/// <summary>
	/// Imports a master private key.
	/// </summary>
	/// <param name="source">The master private key as big-endian bytes, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <param name="hid">The identifier hid of the generating function of the private keys for decryption and key decapsulation; 0x03 by default.</param>
	/// <returns>An instance that holds the master private key and the master public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not in [1, N − 1].</exception>
	public static SM9EncryptionMasterKey ImportPrivateKey(ReadOnlySpan<byte> source, byte hid = SM9Kgc.EncryptionHid)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		if (!FieldElement<SM9Order>.TryImportNonzero(source, out FieldElement<SM9Order> privateKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		SM9EncryptionMasterKey key = FromPrivateKey(in privateKey, hid);
		privateKey.ZeroMemory();
		return key;
	}

	/// <summary>
	/// Imports a master public key.
	/// </summary>
	/// <param name="source">The master public key in the uncompressed encoding, exactly <see cref="PublicKeyLength" /> bytes long.</param>
	/// <param name="hid">The identifier hid of the generating function of the private keys for decryption and key decapsulation; 0x03 by default.</param>
	/// <returns>An instance that holds only the master public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a point on the curve.</exception>
	public static SM9EncryptionMasterKey ImportPublicKey(ReadOnlySpan<byte> source, byte hid = SM9Kgc.EncryptionHid)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PublicKeyLength, nameof(source));

		if (!SM9G1.TryDecode(source, out SM9AffinePoint<SM9Fp> publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		return new SM9EncryptionMasterKey(in publicKey, hid);
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

		SM9G1.Encode(in _publicKey.Point, destination.Slice(0, PublicKeyLength));
		return PublicKeyLength;
	}

	/// <summary>
	/// Extracts the private key of a user for decryption and key decapsulation (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 5.3).
	/// </summary>
	/// <param name="id">The ID of the user, which may have any length.</param>
	/// <returns>The private key of the user, which holds the ID.</returns>
	/// <exception cref="CryptographicException">No key exists for <paramref name="id" /> under the master key and its hid; GM/T 0044 has the key generation center generate a new master key in that case.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the master private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public SM9EncryptionKey ExtractKey(ReadOnlySpan<byte> id)
	{
		ThrowIfNoPrivateKey();

		return new SM9EncryptionKey(Extract(id, _hid), id.ToArray());
	}

	/// <summary>
	/// Extracts the private key of a user for the key exchange (GB/T 38635.2-2020, GM/T 0044.3-2016, Sec. 5.3).
	/// </summary>
	/// <remarks>Both parties of a key exchange need keys of one master key and one hid.</remarks>
	/// <param name="id">The ID of the user, which may have any length.</param>
	/// <param name="hid">The identifier hid of the generating function of the key exchange keys; 0x02 by default.</param>
	/// <returns>The key exchange key of the user, which holds the ID, the master public key and the hid.</returns>
	/// <exception cref="CryptographicException">No key exists for <paramref name="id" /> under the master key and <paramref name="hid" />; GM/T 0044 has the key generation center generate a new master key in that case.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the master private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public SM9KeyExchangeKey ExtractKeyExchangeKey(ReadOnlySpan<byte> id, byte hid = SM9Kgc.KeyExchangeHid)
	{
		ThrowIfNoPrivateKey();

		return new SM9KeyExchangeKey(Extract(id, hid), in _publicKey.Point, id.ToArray(), hid, null);
	}

	/// <summary>
	/// Generates a new random key and its encapsulation to the user of <paramref name="id" /> (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 6.1).
	/// </summary>
	/// <remarks>On failure, both buffers remain unchanged.</remarks>
	/// <param name="encapsulation">The buffer that receives the encapsulation to send to the user, at least <see cref="EncapsulationLength" /> bytes long.</param>
	/// <param name="key">The buffer that receives the key; its length is that of the key, which must not be 0.</param>
	/// <param name="id">The ID of the user.</param>
	/// <exception cref="ArgumentException"><paramref name="encapsulation" /> is too short, <paramref name="key" /> is empty, or they overlap.</exception>
	/// <exception cref="CryptographicException">No key exists for <paramref name="id" /> under the master key and its hid.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Encapsulate(Span<byte> encapsulation, Span<byte> key, ReadOnlySpan<byte> id)
	{
		Encapsulate(encapsulation, key, id, SystemRandom.Fill);
	}

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> to the user of <paramref name="id" /> into C1 ‖ C3 ‖ C2 (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 7.1), with C1 as x ‖ y.
	/// </summary>
	/// <remarks><paramref name="plaintext" /> must not overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="plaintext">The plaintext, which must not be empty.</param>
	/// <param name="destination">The buffer that receives the ciphertext, at least <see cref="GetCiphertextLength" /> bytes long.</param>
	/// <param name="id">The ID of the user.</param>
	/// <returns>The length of the ciphertext, in bytes.</returns>
	/// <exception cref="ArgumentException"><paramref name="plaintext" /> is empty or too long, or <paramref name="destination" /> is too short or overlaps <paramref name="plaintext" />.</exception>
	/// <exception cref="CryptographicException">No key exists for <paramref name="id" /> under the master key and its hid.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> destination, ReadOnlySpan<byte> id)
	{
		return Encrypt(plaintext, destination, id, SystemRandom.Fill);
	}

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> to the user of <paramref name="id" /> into the DER of an SM9Cipher (GB/T 41389-2022), which holds C1, C3 and C2 (GB/T 38635.2-2020, GM/T 0044.4-2016, Sec. 7.1).
	/// </summary>
	/// <remarks><paramref name="plaintext" /> must not overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="plaintext">The plaintext, which must not be empty.</param>
	/// <param name="destination">The buffer that receives the ciphertext, at least <see cref="GetDerCiphertextLength" /> bytes long.</param>
	/// <param name="id">The ID of the user.</param>
	/// <returns>The length of the ciphertext, in bytes.</returns>
	/// <exception cref="ArgumentException"><paramref name="plaintext" /> is empty or too long, or <paramref name="destination" /> is too short or overlaps <paramref name="plaintext" />.</exception>
	/// <exception cref="CryptographicException">No key exists for <paramref name="id" /> under the master key and its hid.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int EncryptDer(ReadOnlySpan<byte> plaintext, Span<byte> destination, ReadOnlySpan<byte> id)
	{
		return EncryptDer(plaintext, destination, id, SystemRandom.Fill);
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
		_base?.Dispose();
		_base = null;
		_disposed = true;
	}

	// GenerateKey with the randomness of fill. If fill throws, nothing is left behind.
	[SkipLocalsInit]
	internal static SM9EncryptionMasterKey GenerateKey(Action<Span<byte>> fill, byte hid)
	{
		Unsafe.SkipInit(out FieldElement<SM9Order> privateKey);

		try
		{
			SM9Kgc.GenerateScalar(fill, out privateKey);
			return FromPrivateKey(in privateKey, hid);
		}
		finally
		{
			privateKey.ZeroMemory();
		}
	}

	// Encapsulate with the randomness of fill. If fill throws, both buffers remain unchanged.
	[SkipLocalsInit]
	internal void Encapsulate(Span<byte> encapsulation, Span<byte> key, ReadOnlySpan<byte> id, Action<Span<byte>> fill)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(encapsulation.Length, EncapsulationLength, nameof(encapsulation));

		if (key.IsEmpty)
		{
			throw new ArgumentException("The key must not be empty.", nameof(key));
		}

		encapsulation = encapsulation.Slice(0, EncapsulationLength);

		if (encapsulation.Overlaps(key))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(key));
		}

		SM9Hash.H1(id, _hid, out FieldElement<SM9Order> h1);
		Span<byte> c = stackalloc byte[EncapsulationLength];
		using CryptoBuffer<byte> first = new(stackalloc byte[SM3KdfState.BlockLength]);
		Unsafe.SkipInit(out SM3KdfState kdf);

		try
		{
			SM9Encryption.DrawEphemeral(_publicKey, in h1, GetBase(), id, key.Length, fill, c, ref kdf, first.Span);
			c.CopyTo(encapsulation);
			SM9Encryption.WriteKeyStream(in kdf, first.Span, key);
		}
		finally
		{
			kdf.Clear();
		}
	}

	// Encrypt with the randomness of fill. If fill throws, destination remains unchanged.
	[SkipLocalsInit]
	internal int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> destination, ReadOnlySpan<byte> id, Action<Span<byte>> fill)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfInvalidPlaintext(plaintext);

		if (plaintext.Length > int.MaxValue - SM9Encryption.CiphertextOverhead)
		{
			ThrowPlaintextTooLong(nameof(plaintext));
		}

		int length = SM9Encryption.CiphertextOverhead + plaintext.Length;
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		if (plaintext.Overlaps(destination))
		{
			ThrowHelper.ThrowInputOutputOverlap(nameof(destination));
		}

		SM9Hash.H1(id, _hid, out FieldElement<SM9Order> h1);
		Span<byte> c1 = stackalloc byte[SM9G1.EncodedLength];
		using CryptoBuffer<byte> first = new(stackalloc byte[SM3KdfState.BlockLength]);
		Unsafe.SkipInit(out SM3KdfState kdf);

		try
		{
			SM9Encryption.DrawEphemeral(_publicKey, in h1, GetBase(), id, plaintext.Length, fill, c1, ref kdf, first.Span);
			c1.Slice(1).CopyTo(destination);
			SM9Encryption.Seal(plaintext, in kdf, first.Span, destination.Slice(SM9Encryption.PointLength, SM9Encryption.HashLength), destination.Slice(SM9Encryption.CiphertextOverhead, plaintext.Length));
			return length;
		}
		finally
		{
			kdf.Clear();
		}
	}

	// EncryptDer with the randomness of fill. If fill throws, destination remains unchanged.
	[SkipLocalsInit]
	internal int EncryptDer(ReadOnlySpan<byte> plaintext, Span<byte> destination, ReadOnlySpan<byte> id, Action<Span<byte>> fill)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfInvalidPlaintext(plaintext);

		int length = SM9Der.GetCipherLength(plaintext.Length);

		if (length < 0)
		{
			ThrowPlaintextTooLong(nameof(plaintext));
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		if (plaintext.Overlaps(destination))
		{
			ThrowHelper.ThrowInputOutputOverlap(nameof(destination));
		}

		SM9Hash.H1(id, _hid, out FieldElement<SM9Order> h1);
		Span<byte> c1 = stackalloc byte[SM9G1.EncodedLength];
		using CryptoBuffer<byte> first = new(stackalloc byte[SM3KdfState.BlockLength]);
		Unsafe.SkipInit(out SM3KdfState kdf);

		try
		{
			SM9Encryption.DrawEphemeral(_publicKey, in h1, GetBase(), id, plaintext.Length, fill, c1, ref kdf, first.Span);
			int written = SM9Der.WriteCipher(c1, plaintext.Length, destination, out int hashOffset, out int cipherTextOffset);
			SM9Encryption.Seal(plaintext, in kdf, first.Span, destination.Slice(hashOffset, SM9Encryption.HashLength), destination.Slice(cipherTextOffset, plaintext.Length));
			return written;
		}
		finally
		{
			kdf.Clear();
		}
	}

	// t2 = ke·t1⁻¹ and de = [t2]P2.
	[SkipLocalsInit]
	private SM9G2PrivateKey Extract(ReadOnlySpan<byte> id, byte hid)
	{
		Unsafe.SkipInit(out FieldElement<SM9Order> scalar);
		Unsafe.SkipInit(out SM9AffinePoint<SM9Fp2> privateKey);

		try
		{
			SM9Kgc.ExtractScalar(in _privateKey, id, hid, out scalar);
			SM9G2.MultiplyBase(in scalar, out privateKey);
			return new SM9G2PrivateKey(in privateKey);
		}
		finally
		{
			scalar.ZeroMemory();
			privateKey.ZeroMemory();
		}
	}

	private SM9GTBase GetBase()
	{
		return _base ?? PublishBase();
	}

	private SM9GTBase PublishBase()
	{
		SM9Pairing.Pair(in _publicKey.Point, in SM9G2.Generator, out SM9Fp12 g);
		SM9GTBase value = new(in g);
		return Interlocked.CompareExchange(ref _base, value, null) ?? value;
	}

	// The master key of ke, with Ppub-e = [ke]P1. Neither the time nor the addresses depend on ke.
	[SkipLocalsInit]
	private static SM9EncryptionMasterKey FromPrivateKey(in FieldElement<SM9Order> privateKey, byte hid)
	{
		SM9G1.MultiplyBase(in privateKey, out SM9AffinePoint<SM9Fp> publicKey);
		return new SM9EncryptionMasterKey(in publicKey, hid) { _privateKey = privateKey, _hasPrivateKey = true };
	}

	private void ThrowIfNoPrivateKey()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (!_hasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("master private key");
		}
	}

	private static void ThrowIfInvalidPlaintext(ReadOnlySpan<byte> plaintext)
	{
		if (plaintext.IsEmpty)
		{
			throw new ArgumentException("The plaintext must not be empty.", nameof(plaintext));
		}
	}

	[DoesNotReturn]
	private static void ThrowPlaintextTooLong(string paramName)
	{
		throw new ArgumentException("The ciphertext would be longer than int.MaxValue bytes.", paramName);
	}
}
