using CryptoBase.EllipticCurves;
using CryptoBase.Macs.Hmac;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Signatures.Ecdsa;

// K, V and the candidates are secret; only the retry after a rejected candidate branches on them.
internal struct EcdsaNonce<THash, TOrder> where THash : unmanaged, IHmacHashCore<THash> where TOrder : unmanaged, IMontgomeryModulus
{
	// Keyed with K.
	private HmacState<THash> _hmac;
	private InlineArray64<byte> _value;
	private bool _hasCandidate;

	[UnscopedRef]
	private Span<byte> V => ((Span<byte>)_value).Slice(0, THash.HashLength);

	// privateKey and hash are ByteLength big-endian bytes each, the hash already truncated and reduced mod n.
	[SkipLocalsInit]
	internal void Initialize(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData)
	{
		Span<byte> key = stackalloc byte[THash.HashLength];
		key.Clear();
		V.Fill(0x01);
		_hmac.Initialize(key, true);
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
				_hmac.Append(V);
				_hmac.GetMacAndReset(V);
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
		_value.ZeroMemory();
		_hasCandidate = false;
	}

	[SkipLocalsInit]
	private void Update(byte separator, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData)
	{
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
}
