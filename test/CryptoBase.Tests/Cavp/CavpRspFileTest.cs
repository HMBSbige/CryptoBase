namespace CryptoBase.Tests.Cavp;

// The well-formed inputs are excerpts of the CAVP SHA-3 and SHAKE response files from
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip and shakebytetestvectors.zip.
public class CavpRspFileTest
{
	[Test]
	[Arguments("\n")]
	[Arguments("\r\n")]
	public async Task ParsesMessageRecordsUnderTheirHeader(string newLine)
	{
		CavpRspFile file = Parse(newLine,
			"#  CAVS 19.0",
			"#  \"SHA3-256 ShortMsg\" information for \"SHA3AllBytes1-28-16\"",
			"",
			"[L = 256]",
			"",
			"Len = 0",
			"Msg = 00",
			"MD = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
			"",
			"Len = 8",
			"Msg = e9",
			"MD = f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6",
			"");

		await Assert.That(file.Records).Count().IsEqualTo(2);

		using (Assert.Multiple())
		{
			await Assert.That(file.Records[0].GetHeaderInt32("L")).IsEqualTo(256);
			await Assert.That(file.Records[0].GetMessage()).IsEmpty();
			await Assert.That(file.Records[0].GetBytes("MD")).IsEquivalentTo(Convert.FromHexString("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), CollectionOrdering.Matching);
			await Assert.That(file.Records[1].GetHeaderInt32("L")).IsEqualTo(256);
			await Assert.That(file.Records[1].GetMessage()).IsEquivalentTo((byte[])[0xE9], CollectionOrdering.Matching);
			await Assert.That(file.Records[1].ToString()).IsEqualTo("Len = 8");
		}
	}

	[Test]
	public async Task ParsesMonteCarloSeedAndCheckpoints()
	{
		CavpRspFile file = Parse("\n",
			"[L = 256]",
			"",
			"Seed = aa64f7245e2177c654eb4de360da8761a516fdc7578c3498c5e582e096b8730c",
			"",
			"COUNT = 0",
			"MD = 225cbac2be6f329d94228c5360a1c177bc495a761c442a1771b1d18555c309a5",
			"",
			"COUNT = 1",
			"MD = 96d364a1b1ced3dbbce6380093fb1ac77221abcee30faf16546ffad8fe1eef8c");

		await Assert.That(file.Records).Count().IsEqualTo(3);

		using (Assert.Multiple())
		{
			await Assert.That(file.Records[0].Contains("Seed")).IsTrue();
			await Assert.That(file.Records[0].Contains("COUNT")).IsFalse();
			await Assert.That(file.Records[1].GetInt32("COUNT")).IsEqualTo(0);
			await Assert.That(file.Records[2].GetInt32("COUNT")).IsEqualTo(1);
			await Assert.That(file.Records[2].GetHeaderInt32("L")).IsEqualTo(256);
		}
	}

	[Test]
	public async Task ParsesVariableOutputHeadersFollowedDirectlyByRecords()
	{
		CavpRspFile file = Parse("\n",
			"[Tested for Output of byte-oriented messages]",
			"[Input Length = 128]",
			"[Minimum Output Length (bits) = 125]",
			"[Maximum Output Length (bits) = 1120]",
			"COUNT = 0",
			"Outputlen = 128",
			"Msg = 84e950051876050dc851fbd99e6247b8",
			"Output = 8599bd89f63a848c49ca593ec37a12c6",
			"",
			"COUNT = 1",
			"Outputlen = 128",
			"Msg = 9a335790abf769877c9e6cd3d5199e8c",
			"Output = 2ece1768a6ef6568a2dff699613f49d0");

		await Assert.That(file.Records).Count().IsEqualTo(2);

		CavpRecord record = file.Records[1];

		using (Assert.Multiple())
		{
			await Assert.That(record.Headers.ContainsKey("Tested for Output of byte-oriented messages")).IsTrue();
			await Assert.That(record.GetHeaderInt32("Input Length")).IsEqualTo(128);
			await Assert.That(record.GetHeaderInt32("Minimum Output Length (bits)")).IsEqualTo(125);
			await Assert.That(record.GetHeaderInt32("Maximum Output Length (bits)")).IsEqualTo(1120);
			await Assert.That(record.GetInt32("Outputlen")).IsEqualTo(128);
			await Assert.That(record.GetBytes("Output")).IsEquivalentTo(Convert.FromHexString("2ece1768a6ef6568a2dff699613f49d0"), CollectionOrdering.Matching);
			await Assert.That(record.ToString()).IsEqualTo("COUNT = 1, Outputlen = 128");
		}
	}

	[Test]
	public async Task HeaderAfterRecordsStartsANewSection()
	{
		CavpRspFile file = Parse("\n",
			"[Outputlen = 128]",
			"",
			"Len = 0",
			"Msg = 00",
			"Output = 7f9c2ba4e88f827d616045507605853e",
			"",
			"[Outputlen = 256]",
			"",
			"Len = 0",
			"Msg = 00",
			"Output = 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

		using (Assert.Multiple())
		{
			await Assert.That(file.Records[0].GetHeaderInt32("Outputlen")).IsEqualTo(128);
			await Assert.That(file.Records[1].GetHeaderInt32("Outputlen")).IsEqualTo(256);
		}
	}

	[Test]
	[Arguments("Len = 8\nLen = 8")]
	[Arguments("[L = 256\nLen = 8")]
	[Arguments("Len 8")]
	public async Task RejectsMalformedInput(string text)
	{
		await Assert.That(() => CavpRspFile.Parse(new StringReader(text))).ThrowsExactly<FormatException>();
	}

	[Test]
	public async Task RejectsBitOrientedMessages()
	{
		CavpRecord record = Parse("\n", "Len = 5", "Msg = 18").Records[0];

		await Assert.That(record.GetMessage).ThrowsExactly<NotSupportedException>();
	}

	private static CavpRspFile Parse(string newLine, params string[] lines)
	{
		return CavpRspFile.Parse(new StringReader(string.Join(newLine, lines)));
	}
}
