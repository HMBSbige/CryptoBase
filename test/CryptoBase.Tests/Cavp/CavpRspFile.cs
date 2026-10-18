namespace CryptoBase.Tests.Cavp;

// Parses NIST CAVP response (.rsp) files, such as those of the SHA3VS:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
// Lines starting with '#' are comments, "[Name = Value]" and "[Name]" lines are section headers,
// and other lines are "Name = Value" fields grouped into records by blank lines or headers.
public sealed class CavpRspFile
{
	private CavpRspFile(IReadOnlyList<CavpRecord> records)
	{
		Records = records;
	}

	public IReadOnlyList<CavpRecord> Records { get; }

	// The files are embedded under their file names; see CryptoBase.Tests.csproj.
	public static CavpRspFile Load(string fileName)
	{
		using Stream stream = typeof(CavpRspFile).Assembly.GetManifestResourceStream(fileName) ?? throw new FileNotFoundException($"CAVP test vectors '{fileName}' are not embedded.", fileName);
		using StreamReader reader = new(stream);
		return Parse(reader);
	}

	public static CavpRspFile Parse(TextReader reader)
	{
		List<CavpRecord> records = [];
		Dictionary<string, string> headers = [];
		Dictionary<string, string> fields = [];
		bool sectionHasRecords = false;

		while (reader.ReadLine() is { } line)
		{
			line = line.Trim();

			if (line.StartsWith('#'))
			{
				continue;
			}

			if (line.Length is 0 || line.StartsWith('['))
			{
				CompleteRecord();
			}

			if (line.StartsWith('['))
			{
				if (!line.EndsWith(']'))
				{
					throw new FormatException($"Unterminated header '{line}'.");
				}

				// A header after records starts a new section rather than extending the current one.
				if (sectionHasRecords)
				{
					headers = [];
					sectionHasRecords = false;
				}

				(string name, string value) = SplitAssignment(line.Substring(1, line.Length - 2), true);
				headers[name] = value;
			}
			else if (line.Length is not 0)
			{
				(string name, string value) = SplitAssignment(line, false);

				if (!fields.TryAdd(name, value))
				{
					throw new FormatException($"Field '{name}' is repeated within a record.");
				}
			}
		}

		CompleteRecord();
		return new CavpRspFile(records);

		void CompleteRecord()
		{
			if (fields.Count is 0)
			{
				return;
			}

			records.Add(new CavpRecord(headers, fields));
			fields = [];
			sectionHasRecords = true;
		}
	}

	private static (string Name, string Value) SplitAssignment(string text, bool allowFlag)
	{
		int separator = text.IndexOf('=');

		if (separator < 0)
		{
			return allowFlag ? (text.Trim(), string.Empty) : throw new FormatException($"Expected 'Name = Value' but found '{text}'.");
		}

		return (text.Substring(0, separator).Trim(), text.Substring(separator + 1).Trim());
	}
}
