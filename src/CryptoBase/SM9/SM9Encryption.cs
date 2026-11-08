using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.Kdf;

namespace CryptoBase.SM9;

// The key encapsulation mechanism and the public key encryption of GB/T 38635.2-2020 (GM/T 0044.4-2016), Sec. 6 and 7, with the stream cipher of the KDF: K = KDF(C ‖ w ‖ ID_B, klen) for the point C, or C1, as x ‖ y, w = e(Ppub-e, P2)^r, K1 the first mlen bits of K and K2 the next 256, C2 = M ⊕ K1 and C3 = MAC(K2, C2) = SM3(C2 ‖ K2). K2 has 256 bits, as in GM/T 0044.5, D.2. Nothing on the paths of r, w, K and M branches on or indexes by them, except the retries that GM/T 0044.4 prescribes for an all-zero K or K1.
internal static class SM9Encryption
{
	private const int MacKeyLength = 32;

	internal const int HashLength = 32;

	// C1 of a ciphertext C1 ‖ C3 ‖ C2 is x ‖ y, as in GM/T 0044.5, D.2.
	internal const int PointLength = 2 * SM9Fp.ByteLength;

	internal const int CiphertextOverhead = PointLength + HashLength;

	// A2 to A6 of Sec. 6.1 and 7.1 for the user public key Q = [h1]P1 + Ppub-e of h1 = H1(ID_B ‖ hid, N) and g = e(Ppub-e, P2): draws r until the first zeroCheckLength bytes of K, K of the encapsulation or K1 of the encryption, are not all zero, and leaves C = [r]Q encoded in c, the KDF over C ‖ w ‖ ID in kdf, and block 1 of K in first. C is [r·h1]P1 + [r]Ppub-e, as SM9G1FixedBase.MultiplyBaseSum gives it; with r in [1, N − 1], it is the point at infinity just if Q is, for an ID that has no key, which throws. Whether those bytes are all zero follows from block 1 unless that is all zero too, which for 32 bytes or more has odds 2^−256, and only that, the retry and the throw branch on it. If fill throws, nothing secret is left behind.
	[SkipLocalsInit]
	internal static void DrawEphemeral(SM9G1FixedBase masterPublicKey, in FieldElement<SM9Order> h1, SM9GTBase g, ReadOnlySpan<byte> id, int zeroCheckLength, Action<Span<byte>> fill, Span<byte> c, ref SM3KdfState kdf, Span<byte> first)
	{
		Debug.Assert(zeroCheckLength > 0 && c.Length is SM9G1.EncodedLength && first.Length is SM3KdfState.BlockLength);

		using CryptoBuffer<byte> w = new(stackalloc byte[SM9GT.EncodedLength]);
		FieldElement<SM9Order>.ToMontgomery(in h1, out FieldElement<SM9Order> factor);
		Unsafe.SkipInit(out FieldElement<SM9Order> r);
		Unsafe.SkipInit(out FieldElement<SM9Order> product);
		Unsafe.SkipInit(out SM9Fp12 power);

		try
		{
			while (true)
			{
				SM9Kgc.GenerateScalar(fill, out r);
				MultiplyUserKey(masterPublicKey, in factor, in r, out product, c);
				g.Power(in r, out power);
				SM9GT.Encode(in power, w.Span);
				kdf.Initialize();
				kdf.Append(c.Slice(1));
				kdf.Append(w.Span);
				kdf.Append(id);
				kdf.WriteBlock(1, first);

				if (SM3KdfState.Accumulate(first.Slice(0, Math.Min(SM3KdfState.BlockLength, zeroCheckLength))) is not 0 || !IsKeyStreamZero(in kdf, zeroCheckLength))
				{
					return;
				}
			}
		}
		finally
		{
			r.ZeroMemory();
			product.ZeroMemory();
			power.ZeroMemory();
		}
	}

	// [r]Q = [r·h1]P1 + [r]Ppub-e encoded in c for Q = [h1]P1 + Ppub-e, from h1 in Montgomery form; throws if [r]Q, so Q, is the point at infinity. product takes r·h1, which the caller erases.
	[SkipLocalsInit]
	internal static void MultiplyUserKey(SM9G1FixedBase masterPublicKey, in FieldElement<SM9Order> factor, in FieldElement<SM9Order> r, out FieldElement<SM9Order> product, Span<byte> c)
	{
		FieldElement<SM9Order>.Multiply(in factor, in r, out product);
		ulong infinity = masterPublicKey.MultiplyBaseSum(in product, in r, out SM9AffinePoint<SM9Fp> point);

		if (infinity is not 0)
		{
			SM9Kgc.ThrowNoKey();
		}

		SM9G1.Encode(in point, c);
	}

	// B1 and B2 of Sec. 6.2 and 7.2 and the KDF of B3: C, encoded, lies on the curve, which has cofactor 1, so in G1, and kdf absorbs C ‖ w' ‖ ID with w' = e(C, de). Returns false, absorbing nothing, if C does not decode.
	[SkipLocalsInit]
	internal static bool TryStart(ReadOnlySpan<byte> c, SM9G2PrivateKey key, ReadOnlySpan<byte> id, ref SM3KdfState kdf)
	{
		if (!SM9G1.TryDecode(c, out SM9AffinePoint<SM9Fp> point))
		{
			return false;
		}

		using CryptoBuffer<byte> w = new(stackalloc byte[SM9GT.EncodedLength]);
		key.PairVariableTime(in point, out SM9Fp12 power);
		SM9GT.Encode(in power, w.Span);
		power.ZeroMemory();
		kdf.Initialize();
		kdf.Append(c.Slice(1));
		kdf.Append(w.Span);
		kdf.Append(id);
		return true;
	}

	// B3 of Sec. 6.2: writes K' to key unless it is all zero, for kdf from TryStart; returns false, writing nothing, if it is.
	[SkipLocalsInit]
	internal static bool TryWriteKey(in SM3KdfState kdf, Span<byte> key)
	{
		using CryptoBuffer<byte> first = new(stackalloc byte[SM3KdfState.BlockLength]);
		kdf.WriteBlock(1, first.Span);

		if (SM3KdfState.Accumulate(first.Span.Slice(0, Math.Min(SM3KdfState.BlockLength, key.Length))) is 0 && IsKeyStreamZero(in kdf, key.Length))
		{
			return false;
		}

		WriteKeyStream(in kdf, first.Span, key);
		return true;
	}

	// Writes the key stream of kdf to destination, taking block 1 from first.
	internal static void WriteKeyStream(in SM3KdfState kdf, ReadOnlySpan<byte> first, Span<byte> destination)
	{
		int length = destination.Length;
		first.Slice(0, Math.Min(SM3KdfState.BlockLength, length)).CopyTo(destination);

		if (length > SM3KdfState.BlockLength)
		{
			kdf.Write(2, destination.Slice(SM3KdfState.BlockLength));
		}
	}

	// A6 to A8 of Sec. 7.1: C2 = M ⊕ K1 and C3 = SM3(C2 ‖ K2), from block 1 of K in first and the next ones from kdf. c2 does not overlap plaintext.
	[SkipLocalsInit]
	internal static void Seal(ReadOnlySpan<byte> plaintext, in SM3KdfState kdf, ReadOnlySpan<byte> first, Span<byte> c3, Span<byte> c2)
	{
		int length = plaintext.Length;
		using CryptoBuffer<byte> macKey = new(stackalloc byte[MacKeyLength]);
		FastUtils.Xor(first, plaintext, c2, Math.Min(SM3KdfState.BlockLength, length));

		if (length > SM3KdfState.BlockLength)
		{
			kdf.Xor(2, plaintext.Slice(SM3KdfState.BlockLength), c2.Slice(SM3KdfState.BlockLength));
		}

		ReadKeyStream(in kdf, length, macKey.Span);
		Mac(c2, macKey.Span, c3);
	}

	// B1 to B5 of Sec. 7.2 for C1 encoded and a C2 that is not empty: writes M' to the first C2.Length bytes of destination and returns true if C1 lies on the curve, K1' is not all zero and C3 = SM3(C2 ‖ K2'), which it compares in fixed time; otherwise returns false and writes nothing. destination may overlap the ciphertext: M' goes there only after the last read of it.
	[SkipLocalsInit]
	internal static bool Open(ReadOnlySpan<byte> c1, ReadOnlySpan<byte> c3, ReadOnlySpan<byte> c2, SM9G2PrivateKey key, ReadOnlySpan<byte> id, Span<byte> destination)
	{
		Debug.Assert(c3.Length is HashLength && !c2.IsEmpty && destination.Length >= c2.Length);

		Unsafe.SkipInit(out SM3KdfState kdf);

		if (!TryStart(c1, key, id, ref kdf))
		{
			return false;
		}

		int length = c2.Length;
		using CryptoBuffer<byte> macKey = new(stackalloc byte[MacKeyLength]);
		using CryptoBuffer<byte> plaintext = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		Span<byte> mac = stackalloc byte[HashLength];

		try
		{
			// B3: M' = C2 ⊕ K1', and whether K1', of length bytes, is all zero.
			ulong keyStream = kdf.Xor(1, c2, plaintext.Span);

			// B4: u = SM3(C2 ‖ K2').
			ReadKeyStream(in kdf, length, macKey.Span);
			Mac(c2, macKey.Span, mac);

			if (LimbArithmetic.ZeroMask(keyStream) is not 0 | !FixedTime.Equals(mac, c3))
			{
				return false;
			}

			plaintext.Span.CopyTo(destination);
			return true;
		}
		finally
		{
			kdf.Clear();
			mac.Clear();
		}
	}

	// Whether the blocks of K from 2 on are all zero within length bytes.
	private static bool IsKeyStreamZero(in SM3KdfState kdf, int length)
	{
		return length <= SM3KdfState.BlockLength || kdf.IsZero(2, length - SM3KdfState.BlockLength);
	}

	// Writes the bytes of the key stream of kdf from offset on, which fill destination: K2 from mlen on. It spans at most two blocks, which only offset decides.
	[SkipLocalsInit]
	private static void ReadKeyStream(in SM3KdfState kdf, int offset, Span<byte> destination)
	{
		using CryptoBuffer<byte> block = new(stackalloc byte[SM3KdfState.BlockLength]);
		uint counter = (uint)(offset / SM3KdfState.BlockLength) + 1;
		int start = offset % SM3KdfState.BlockLength;

		for (int written = 0; written < destination.Length; start = 0)
		{
			kdf.WriteBlock(counter++, block.Span);
			int count = Math.Min(SM3KdfState.BlockLength - start, destination.Length - written);
			block.Span.Slice(start, count).CopyTo(destination.Slice(written));
			written += count;
		}
	}

	// MAC(K2, Z) = SM3(Z ‖ K2) of Sec. 5.4.5.
	[SkipLocalsInit]
	private static void Mac(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, Span<byte> destination)
	{
		SM3Core hash = HashCore.Create<SM3Core>();
		HashCore.Append(ref hash, message);
		HashCore.Append(ref hash, key);
		HashCore.Finalize(ref hash, destination);
		hash.ZeroMemory();
	}
}
