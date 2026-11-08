using CryptoBase.X509;
using System.Formats.Asn1;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.X509;

// What DerReader reads without AsnDecoder is what AsnDecoder accepts.
public class DerReaderTest
{
	public static IEnumerable<Func<(string Case, byte[] Contents, bool Accepted)>> ObjectIdentifierLimits()
	{
		yield return () => ("63 subidentifiers, which are 64 arcs", Filled(63, 0x2A), true);
		yield return () => ("64 subidentifiers, which are 65 arcs", Filled(64, 0x2A), false);
		yield return () => ("a subidentifier of 128 bits", [0x2A, 0x83, .. Filled(17, 0xFF), 0x7F], true);
		yield return () => ("a subidentifier of 129 bits", [0x2A, 0x84, .. Filled(17, 0xFF), 0x7F], false);
		yield return () => ("a subidentifier of 21 octets", [0x2A, .. Filled(20, 0xFF), 0x7F], false);
		yield return () => ("18 octets, the most read without AsnDecoder", Filled(18, 0x2A), true);
		yield return () => ("19 octets", Filled(19, 0x2A), true);
		yield return () => ("18 octets of one subidentifier", [.. Filled(17, 0xFF), 0x7F], true);
		yield return () => ("no contents", [], false);
		yield return () => ("a leading zero in a subidentifier", [0x2A, 0x80, 0x01], false);
		yield return () => ("an incomplete last subidentifier", [0x2A, 0x81], false);
	}

	[Test]
	[MethodDataSource(nameof(ObjectIdentifierLimits))]
	public async Task ReadsObjectIdentifiersWithinTheLimitsOfTheBcl(string @case, byte[] contents, bool accepted)
	{
		byte[] encoded = Tlv(0x06, contents);

		using (Assert.Multiple())
		{
			await Assert.That(ReadWithTheBcl(encoded) is not null).IsEqualTo(accepted).Because($"{@case}: AsnDecoder");
			await Assert.That(Skip(encoded) is not null).IsEqualTo(accepted).Because($"{@case}: SkipObjectIdentifier");
			await Assert.That(ReadContents(encoded) is not null).IsEqualTo(accepted).Because($"{@case}: ReadObjectIdentifierContents");
		}
	}

	// Random contents that reach the limits of AsnDecoder: many subidentifiers of one octet, or a run of continuation octets as long as one of 126 to 133 bits, or what is often wrong in an identifier; then another value after it, or truncated, or with another tag.
	[Test]
	public async Task ObjectIdentifierReadersAgreeWithTheBcl()
	{
		Random random = new(0x5A17);
		List<string> differences = [];

		for (int i = 0; i < 40_000; ++i)
		{
			byte[] contents = random.Next(3) switch
			{
				0 => ManySubidentifiers(random),
				1 => LongSubidentifier(random),
				_ => Mixed(random)
			};

			byte tag = random.Next(8) is 0 ? (byte)0x26 : (byte)0x06;
			byte[] encoded = [.. Tlv(tag, contents), 0x05, 0x00];
			encoded = random.Next(8) is 0 ? encoded.AsSpan(0, random.Next(encoded.Length)).ToArray() : encoded;

			int? consumed = ReadWithTheBcl(encoded);
			(int Consumed, byte[] Contents)? read = ReadContents(encoded);

			if (Skip(encoded) != consumed || read?.Consumed != consumed || read is { } value && !value.Contents.AsSpan().SequenceEqual(ContentsOf(encoded)))
			{
				differences.Add(Convert.ToHexString(encoded));
			}
		}

		await Assert.That(differences).IsEmpty();
	}

	private static byte[] ManySubidentifiers(Random random)
	{
		byte[] contents = new byte[random.Next(60, 68)];

		for (int j = 0; j < contents.Length; ++j)
		{
			contents[j] = (byte)random.Next(0x80);
		}

		return contents;
	}

	// An arc before a subidentifier of 18 to 19 octets, the first of which decides how many of the bits it uses.
	private static byte[] LongSubidentifier(Random random)
	{
		byte[] contents = new byte[random.Next(19, 22)];
		contents[0] = 0x2A;
		contents[1] = (byte)(random.Next(2) is 0 ? random.Next(0x81, 0x88) : 0xFF);

		for (int j = 2; j < contents.Length - 1; ++j)
		{
			contents[j] = (byte)random.Next(0x80, 0x100);
		}

		contents[^1] = (byte)random.Next(0x80);
		return contents;
	}

	private static byte[] Mixed(Random random)
	{
		byte[] contents = new byte[random.Next(0, 32)];

		for (int j = 0; j < contents.Length; ++j)
		{
			contents[j] = (byte)(random.Next(4) switch
			{
				0 => 0x80,
				1 => random.Next(0x81, 0x100),
				_ => random.Next(0x80)
			});
		}

		if (contents.Length > 0 && random.Next(4) is not 0)
		{
			contents[^1] &= 0x7F;
		}

		return contents;
	}

	private static byte[] Filled(int count, byte value)
	{
		return [.. Enumerable.Repeat(value, count)];
	}

	private static byte[] ContentsOf(byte[] encoded)
	{
		AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out int offset, out int length, out _);
		return encoded.AsSpan(offset, length).ToArray();
	}

	// The bytes that AsnDecoder reads, or null if it refuses the value.
	private static int? ReadWithTheBcl(byte[] encoded)
	{
		try
		{
			AsnDecoder.ReadObjectIdentifier(encoded, AsnEncodingRules.DER, out int consumed);
			return consumed;
		}
		catch (AsnContentException)
		{
			return null;
		}
	}

	private static int? Skip(byte[] encoded)
	{
		try
		{
			DerReader reader = new(encoded);
			reader.SkipObjectIdentifier();
			return encoded.Length - reader.GetRemaining().Length;
		}
		catch (AsnContentException)
		{
			return null;
		}
	}

	private static (int Consumed, byte[] Contents)? ReadContents(byte[] encoded)
	{
		try
		{
			DerReader reader = new(encoded);
			byte[] contents = reader.ReadObjectIdentifierContents().ToArray();
			return (encoded.Length - reader.GetRemaining().Length, contents);
		}
		catch (AsnContentException)
		{
			return null;
		}
	}
}
