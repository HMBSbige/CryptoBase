using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoBase.Tests.X509.Limbo;

// The testcases of x509-limbo (https://github.com/C2SP/x509-limbo), from the limbo.json of the submodule, read once. Only the fields that the harness uses are read; limbo-schema.json describes them all.
internal static partial class LimboTestcases
{
	private static readonly Lazy<LimboFile> File = new(Load);

	public static IReadOnlyList<LimboTestcase> All => File.Value.Testcases;

	private static LimboFile Load()
	{
		string path = typeof(LimboTestcases).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(static attribute => attribute.Key is "X509LimboTestcases").Value ?? throw new InvalidOperationException("The x509-limbo testcases are not set.");

		if (!System.IO.File.Exists(path))
		{
			throw new FileNotFoundException("The x509-limbo testcases were not found. Run 'git submodule update --init --depth 1 test/x509-limbo'.", path);
		}

		using FileStream stream = System.IO.File.OpenRead(path);
		LimboFile file = JsonSerializer.Deserialize(stream, LimboJsonContext.Default.LimboFile) ?? throw new JsonException("limbo.json is empty.");
		return file.Version is 1 ? file : throw new JsonException($"limbo.json has version {file.Version}, not 1.");
	}

	[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
	[JsonSerializable(typeof(LimboFile))]
	private sealed partial class LimboJsonContext : JsonSerializerContext;
}

internal sealed class LimboFile
{
	public int Version { get; init; }

	public LimboTestcase[] Testcases { get; init; } = [];
}

internal sealed class LimboTestcase
{
	public string Id { get; init; } = "";

	public string[] Features { get; init; } = [];

	public string ValidationKind { get; init; } = "";

	public string[] TrustedCerts { get; init; } = [];

	public string[] UntrustedIntermediates { get; init; } = [];

	public string PeerCertificate { get; init; } = "";

	public DateTimeOffset? ValidationTime { get; init; }

	public string[] SignatureAlgorithms { get; init; } = [];

	public string[] KeyUsage { get; init; } = [];

	public string[] ExtendedKeyUsage { get; init; } = [];

	public string ExpectedResult { get; init; } = "";

	public LimboPeerName? ExpectedPeerName { get; init; }

	public int? MaxChainDepth { get; init; }

	public string[] Crls { get; init; } = [];

	public override string ToString()
	{
		return Id;
	}
}

internal sealed class LimboPeerName
{
	public string Kind { get; init; } = "";

	public string Value { get; init; } = "";
}
