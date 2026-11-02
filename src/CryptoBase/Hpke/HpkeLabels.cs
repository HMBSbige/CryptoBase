using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;

namespace CryptoBase.Hpke;

// LabeledExtract and LabeledExpand of RFC 9180, Section 4, over HKDF with the hash of TKdf.
internal static class HpkeLabels
{
	private static ReadOnlySpan<byte> Version => "HPKE-v1"u8;

	// Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm). The empty salt that most labels take starts from the HMAC state of the empty key, which is the same every time.
	internal static void Extract<TKdf>(ReadOnlySpan<byte> suiteId, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> label, ReadOnlySpan<byte> inputKeyMaterial, Span<byte> pseudorandomKey) where TKdf : unmanaged, IHmacHashCore<TKdf>
	{
		Debug.Assert(pseudorandomKey.Length == TKdf.HashLength);

		Unsafe.SkipInit(out HmacState<TKdf> hmac);

		try
		{
			if (salt.IsEmpty)
			{
				hmac = EmptyKey<TKdf>.State;
			}
			else
			{
				hmac.Initialize(salt, false);
			}

			hmac.Append(Version);
			hmac.Append(suiteId);
			hmac.Append(label);
			hmac.Append(inputKeyMaterial);
			hmac.GetMacDestructive(pseudorandomKey);
		}
		finally
		{
			hmac.ZeroMemory();
		}
	}

	// Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L) for L = output.Length in [1, 255·Nh]. Only info may overlap output.
	[SkipLocalsInit]
	internal static void Expand<TKdf>(ReadOnlySpan<byte> suiteId, ReadOnlySpan<byte> pseudorandomKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> info, Span<byte> output) where TKdf : unmanaged, IHmacHashCore<TKdf>
	{
		Debug.Assert(output.Length > 0 && output.Length <= 255 * TKdf.HashLength);

		if (output.Length > TKdf.HashLength)
		{
			Span<byte> prefix = stackalloc byte[PrefixLength(suiteId, label)];
			WritePrefix(suiteId, label, output.Length, prefix);
			ExpandBlocks<TKdf>(pseudorandomKey, prefix, info, output);
			return;
		}

		Unsafe.SkipInit(out HmacState<TKdf> hmac);

		try
		{
			hmac.Initialize(pseudorandomKey, false);
			Expand(ref hmac, suiteId, label, info, output);
		}
		finally
		{
			hmac.ZeroMemory();
		}
	}

	// As above for L of at most Nh, T(1) = HMAC(prk, labeled_info ‖ 0x01), from a state keyed with prk, which it leaves keyed for the next label of the same key. output is written after the last read of info.
	[SkipLocalsInit]
	internal static void Expand<TKdf>(ref HmacState<TKdf> keyed, ReadOnlySpan<byte> suiteId, ReadOnlySpan<byte> label, ReadOnlySpan<byte> info, Span<byte> output) where TKdf : unmanaged, IHmacHashCore<TKdf>
	{
		Debug.Assert(output.Length > 0 && output.Length <= TKdf.HashLength);

		Span<byte> prefix = stackalloc byte[PrefixLength(suiteId, label)];
		WritePrefix(suiteId, label, output.Length, prefix);
		using CryptoBuffer<byte> block = new(stackalloc byte[TKdf.HashLength]);
		keyed.Append(prefix);
		keyed.Append(info);
		keyed.Append([1]);
		keyed.GetMacAndResetDestructive(block.Span);
		block.Span.Slice(0, output.Length).CopyTo(output);
	}

	private static int PrefixLength(ReadOnlySpan<byte> suiteId, ReadOnlySpan<byte> label)
	{
		return sizeof(ushort) + Version.Length + suiteId.Length + label.Length;
	}

	// I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label.
	private static void WritePrefix(ReadOnlySpan<byte> suiteId, ReadOnlySpan<byte> label, int length, Span<byte> prefix)
	{
		BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)length);
		Version.CopyTo(prefix.Slice(sizeof(ushort)));
		suiteId.CopyTo(prefix.Slice(sizeof(ushort) + Version.Length));
		label.CopyTo(prefix.Slice(sizeof(ushort) + Version.Length + suiteId.Length));
	}

	// Later blocks read info again, so the labeled info is copied before output is written.
	[SkipLocalsInit]
	private static void ExpandBlocks<TKdf>(ReadOnlySpan<byte> pseudorandomKey, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> info, Span<byte> output) where TKdf : unmanaged, IHmacHashCore<TKdf>
	{
		int length = checked(prefix.Length + info.Length);
		using CryptoBuffer<byte> labeledInfo = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		prefix.CopyTo(labeledInfo.Span);
		info.CopyTo(labeledInfo.Span.Slice(prefix.Length));
		Hkdf.ExpandCore<TKdf>(pseudorandomKey, output, labeledInfo.Span);
	}

	// HMAC keyed with the empty salt, a block of zeros, which holds no secret.
	private static class EmptyKey<TKdf> where TKdf : unmanaged, IHmacHashCore<TKdf>
	{
		internal static readonly HmacState<TKdf> State = Create();

		private static HmacState<TKdf> Create()
		{
			HmacState<TKdf> state = default;
			state.Initialize(default, false);
			return state;
		}
	}
}
