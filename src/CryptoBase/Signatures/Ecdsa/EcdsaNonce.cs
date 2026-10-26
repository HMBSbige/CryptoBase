using CryptoBase.EllipticCurves;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Signatures.Ecdsa;

// K, V and the candidates are secret; only the retry after a rejected candidate branches on them. HMAC-SHA256 goes to HMACSHA256 where the platform is faster for these short messages.
internal struct EcdsaNonce<THash, TOrder> where THash : unmanaged, IHmacHashCore<THash> where TOrder : unmanaged, IMontgomeryModulus
{
	// The longest message to K that goes to HMACSHA256; it holds 32 bytes of additional data on every curve, and longer messages take the managed HMAC.
	private const int MaxPlatformMessageLength = 256;

	// Most MACs of a nonce take V alone, so the platform takes them all where it is faster for V.
	private static readonly bool PlatformPreferred = typeof(THash) == typeof(Sha256Core) && PlatformHmacSha256.IsPreferredFor(Sha256Core.HashSizeInBytes);

	// Keyed with the zero K that every nonce starts from.
	private static readonly HmacState<THash> ZeroKeyHmac = CreateZeroKeyHmac();

	// Keyed with K for the managed HMAC.
	private HmacState<THash> _hmac;
	// K for HMACSHA256.
	private InlineArray32<byte> _key;
	private InlineArray64<byte> _value;
	private bool _hasCandidate;
	private bool _platform;

	[UnscopedRef]
	private Span<byte> K => _key;

	[UnscopedRef]
	private Span<byte> V => ((Span<byte>)_value).Slice(0, THash.HashLength);

	// privateKey and hash are ByteLength big-endian bytes each, the hash already truncated and reduced mod n.
	internal void Initialize(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData)
	{
		V.Fill(0x01);
		_platform = PlatformPreferred && THash.HashLength + 1 + privateKey.Length + hash.Length + additionalData.Length <= MaxPlatformMessageLength;

		if (_platform)
		{
			K.Clear();
		}
		else
		{
			_hmac = ZeroKeyHmac;
		}

		Update(0x00, privateKey, hash, additionalData);
		Update(0x01, privateKey, hash, additionalData);
		_hasCandidate = false;
	}

	// Each call after the first moves on from the last candidate, as needed when it gave r = 0 or s = 0.
	[SkipLocalsInit]
	internal void Next(out FieldElement<TOrder> result)
	{
		int length = TOrder.ByteLength;
		int hashLength = THash.HashLength;
		using CryptoBuffer<byte> buffer = new(stackalloc byte[2 * length + hashLength]);
		Span<byte> candidate = buffer.Span.Slice(0, length);
		Span<byte> blocks = buffer.Span.Slice(length);

		while (true)
		{
			if (_hasCandidate)
			{
				Update(0x00, [], [], []);
			}

			_hasCandidate = true;
			int blocksLength = 0;

			for (; 8 * blocksLength < TOrder.BitLength; blocksLength += hashLength)
			{
				if (_platform)
				{
					PlatformMac(V, V);
				}
				else
				{
					_hmac.Append(V);
					_hmac.GetMacAndReset(V);
				}

				V.CopyTo(blocks.Slice(blocksLength));
			}

			EcdsaEncoding<TOrder>.Truncate(blocks.Slice(0, blocksLength), candidate);

			if (FieldElement<TOrder>.TryImportNonzero(candidate, out result))
			{
				return;
			}
		}
	}

	internal void Clear()
	{
		_hmac.ZeroMemory();
		_key.ZeroMemory();
		_value.ZeroMemory();
		_hasCandidate = false;
	}

	private static HmacState<THash> CreateZeroKeyHmac()
	{
		Span<byte> key = stackalloc byte[THash.HashLength];
		key.Clear();
		HmacState<THash> hmac = default;
		hmac.Initialize(key, true);
		return hmac;
	}

	[SkipLocalsInit]
	private void Update(byte separator, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData)
	{
		if (_platform)
		{
			PlatformUpdate(separator, privateKey, hash, additionalData);
			return;
		}

		using CryptoBuffer<byte> key = new(stackalloc byte[THash.HashLength]);
		_hmac.Append(V);
		_hmac.Append(new ReadOnlySpan<byte>(in separator));
		_hmac.Append(privateKey);
		_hmac.Append(hash);
		_hmac.Append(additionalData);
		_hmac.GetMacAndReset(key.Span);
		_hmac.Initialize(key.Span, true);
		_hmac.Append(V);
		_hmac.GetMacAndReset(V);
	}

	[SkipLocalsInit]
	private void PlatformUpdate(byte separator, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData)
	{
		Span<byte> value = V;
		using CryptoBuffer<byte> buffer = new(stackalloc byte[MaxPlatformMessageLength]);
		Span<byte> message = buffer.Span.Slice(0, value.Length + 1 + privateKey.Length + hash.Length + additionalData.Length);
		value.CopyTo(message);
		message[value.Length] = separator;
		privateKey.CopyTo(message.Slice(value.Length + 1));
		hash.CopyTo(message.Slice(value.Length + 1 + privateKey.Length));
		additionalData.CopyTo(message.Slice(message.Length - additionalData.Length));
		PlatformMac(message, K);
		PlatformMac(value, value);
	}

	// HMAC_K(source), through a temporary buffer, as destination may overlap K or source.
	[SkipLocalsInit]
	private readonly void PlatformMac(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		using CryptoBuffer<byte> mac = new(stackalloc byte[HMACSHA256.HashSizeInBytes]);
		HMACSHA256.HashData(_key, source, mac.Span);
		mac.Span.CopyTo(destination);
	}
}
