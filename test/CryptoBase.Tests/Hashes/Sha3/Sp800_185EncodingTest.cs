using CryptoBase.Hashes.Sha3;
using System.Buffers.Binary;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sp800_185EncodingTest
{
	// Values whose encodings change length, and the extremes below 2^56, whose encodings fill a word.
	public static IEnumerable<(ulong Value, int EncodedLength)> Values =>
	[
		(0, 2), (1, 2), (127, 2), (128, 2), (255, 2),
		(256, 3), (65535, 3),
		(65536, 4), (0xFFFFFF, 4),
		(0x1000000, 5), (uint.MaxValue, 5),
		(1UL << 32, 6),
		(1UL << 40, 7),
		(1UL << 48, 8), ((1UL << 56) - 1, 8)
	];

	public static IEnumerable<ulong> EncodedValues => Values.Select(static entry => entry.Value);

	// SP 800-185, Sec. 2.3.1 gives left_encode(0) and right_encode(0); the rates are the first bytes of the bytepad data in the cSHAKE examples.
	[Test]
	[Arguments(0UL, "0100", "0001")]
	[Arguments(168UL, "01A8", "A801")]
	[Arguments(136UL, "0188", "8801")]
	[Arguments(256UL, "020100", "010002")]
	public async Task EncodesKnownValues(ulong value, string expectedLeft, string expectedRight)
	{
		using (Assert.Multiple())
		{
			await Assert.That(LeftEncode(value)).IsEquivalentTo(Convert.FromHexString(expectedLeft), CollectionOrdering.Matching);
			await Assert.That(RightEncode(value)).IsEquivalentTo(Convert.FromHexString(expectedRight), CollectionOrdering.Matching);
		}
	}

	// Decoding recovers the value from the fewest bytes that hold it, and the encodings agree with the transcription of the specification.
	[Test]
	[MethodDataSource(nameof(Values))]
	public async Task EncodingsRoundTripInFewestBytes(ulong value, int encodedLength)
	{
		byte[] left = LeftEncode(value);
		byte[] right = RightEncode(value);

		using (Assert.Multiple())
		{
			await Assert.That(left.Length).IsEqualTo(encodedLength);
			await Assert.That(left[0]).IsEqualTo((byte)(encodedLength - 1));
			await Assert.That(DecodeBigEndian(left.AsSpan(1))).IsEqualTo(value);
			await Assert.That(right.Length).IsEqualTo(encodedLength);
			await Assert.That(right[^1]).IsEqualTo((byte)(encodedLength - 1));
			await Assert.That(DecodeBigEndian(right.AsSpan(0, encodedLength - 1))).IsEqualTo(value);
			await Assert.That(left.AsSpan(1).ToArray()).IsEquivalentTo(right.AsSpan(0, encodedLength - 1).ToArray(), CollectionOrdering.Matching);
			await Assert.That(left).IsEquivalentTo(KeccakReference.LeftEncode(value), CollectionOrdering.Matching);
			await Assert.That(right).IsEquivalentTo(KeccakReference.RightEncode(value), CollectionOrdering.Matching);
		}
	}

	// The sponge XORs the whole word into its state, which the bytes past the encoding leave unchanged only if they are zero.
	[Test]
	[MethodDataSource(nameof(EncodedValues))]
	public async Task LeavesTheRestOfTheWordZero(ulong value)
	{
		int length = Sp800_185Encoding.EncodedLength(value);

		using (Assert.Multiple())
		{
			await Assert.That(Bytes(Sp800_185Encoding.LeftEncode(value)).AsSpan(length).ToArray()).All(static b => b is 0);
			await Assert.That(Bytes(Sp800_185Encoding.RightEncode(value)).AsSpan(length).ToArray()).All(static b => b is 0);
		}
	}

	private static byte[] LeftEncode(ulong value)
	{
		return Bytes(Sp800_185Encoding.LeftEncode(value)).AsSpan(0, Sp800_185Encoding.EncodedLength(value)).ToArray();
	}

	private static byte[] RightEncode(ulong value)
	{
		return Bytes(Sp800_185Encoding.RightEncode(value)).AsSpan(0, Sp800_185Encoding.EncodedLength(value)).ToArray();
	}

	// The bytes of an encoding in the order that the sponge absorbs them.
	private static byte[] Bytes(ulong encoded)
	{
		byte[] bytes = new byte[sizeof(ulong)];
		BinaryPrimitives.WriteUInt64LittleEndian(bytes, encoded);
		return bytes;
	}

	// Rejects a leading zero digit, which a longer encoding than needed would have.
	private static ulong DecodeBigEndian(ReadOnlySpan<byte> digits)
	{
		if (digits.Length is 0 or > sizeof(ulong) || digits.Length > 1 && digits[0] is 0)
		{
			throw new FormatException($"{Convert.ToHexString(digits)} is not a minimal encoding.");
		}

		Span<byte> padded = stackalloc byte[sizeof(ulong)];
		padded.Clear();
		digits.CopyTo(padded.Slice(sizeof(ulong) - digits.Length));
		return BinaryPrimitives.ReadUInt64BigEndian(padded);
	}
}
