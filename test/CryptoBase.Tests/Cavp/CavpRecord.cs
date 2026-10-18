using System.Globalization;

namespace CryptoBase.Tests.Cavp;

public sealed class CavpRecord
{
	internal CavpRecord(IReadOnlyDictionary<string, string> headers, IReadOnlyDictionary<string, string> fields)
	{
		Headers = headers;
		Fields = fields;
	}

	// The section headers in effect for this record, such as "L" or "Outputlen"; a header without a value maps to "".
	public IReadOnlyDictionary<string, string> Headers { get; }

	public IReadOnlyDictionary<string, string> Fields { get; }

	public bool Contains(string name)
	{
		return Fields.ContainsKey(name);
	}

	public string GetString(string name)
	{
		return Fields.TryGetValue(name, out string? value) ? value : throw new KeyNotFoundException($"The record has no '{name}' field.");
	}

	public int GetInt32(string name)
	{
		return int.Parse(GetString(name), NumberStyles.None, CultureInfo.InvariantCulture);
	}

	public byte[] GetBytes(string name)
	{
		return Convert.FromHexString(GetString(name));
	}

	public int GetHeaderInt32(string name)
	{
		return Headers.TryGetValue(name, out string? value)
			? int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture)
			: throw new KeyNotFoundException($"The record has no '{name}' header.");
	}

	// "Len" counts bits, and the empty message is written "Msg = 00", so the message is the first Len / 8 bytes of "Msg".
	public byte[] GetMessage()
	{
		int length = GetInt32("Len");

		if (length % 8 is not 0)
		{
			throw new NotSupportedException($"The {length}-bit message is not byte-aligned.");
		}

		byte[] message = GetBytes("Msg");
		return message.Length >= length / 8 ? message.AsSpan(0, length / 8).ToArray() : throw new FormatException($"'Msg' is shorter than {length} bits.");
	}

	public override string ToString()
	{
		return string.Join(", ", new[] { "COUNT", "Len", "Outputlen" }.Where(Contains).Select(name => $"{name} = {GetString(name)}"));
	}
}
