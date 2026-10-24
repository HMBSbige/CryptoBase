using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace CryptoBase.Tests.Wycheproof;

internal static partial class WycheproofVectors
{
	private static readonly string VectorsDirectory = typeof(WycheproofVectors).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(static attribute => attribute.Key is "WycheproofTestVectors").Value ?? throw new InvalidOperationException("The Wycheproof test vector directory is not set.");

	public static IEnumerable<T> Load<T>(string fileName) where T : WycheproofTestVector
	{
		return Load<TestFile<T>>(fileName, typeof(T)).TestGroups.SelectMany(static group => group.Tests);
	}

	// For files whose groups hold what their tests share, such as a key.
	public static IEnumerable<T> Load<TGroup, T>(string fileName) where TGroup : WycheproofTestGroup<T> where T : WycheproofTestVector
	{
		return Load<GroupFile<TGroup>>(fileName, typeof(TGroup)).TestGroups.SelectMany(static group => group.Tests.Select(group.Complete));
	}

	private static TFile Load<TFile>(string fileName, Type registeredType) where TFile : class
	{
		string path = Path.Combine(VectorsDirectory, fileName);

		if (!File.Exists(path))
		{
			throw new FileNotFoundException($"Wycheproof test vectors '{fileName}' were not found. Run 'git submodule update --init'.", path);
		}

		JsonTypeInfo<TFile> typeInfo = (JsonTypeInfo<TFile>)(VectorsJsonContext.Default.GetTypeInfo(typeof(TFile)) ?? throw new NotSupportedException($"{registeredType.Name} is not registered in {nameof(VectorsJsonContext)}."));

		using FileStream stream = File.OpenRead(path);
		return JsonSerializer.Deserialize(stream, typeInfo) ?? throw new JsonException($"{fileName} is empty.");
	}

	private sealed record TestFile<T>(TestGroup<T>[] TestGroups);

	private sealed record TestGroup<T>(T[] Tests);

	private sealed record GroupFile<TGroup>(TGroup[] TestGroups);

	[JsonSourceGenerationOptions
	(
		JsonSerializerDefaults.Web,
		RespectNullableAnnotations = true,
		RespectRequiredConstructorParameters = true,
		UseStringEnumConverter = true,
		Converters = [typeof(HexConverter)]
	)]
	[JsonSerializable(typeof(TestFile<AeadTestVector>))]
	[JsonSerializable(typeof(TestFile<IndCpaTestVector>))]
	[JsonSerializable(typeof(TestFile<MacTestVector>))]
	[JsonSerializable(typeof(TestFile<HkdfTestVector>))]
	[JsonSerializable(typeof(TestFile<EcCurveTestVector>))]
	[JsonSerializable(typeof(TestFile<EcdhEcpointTestVector>))]
	[JsonSerializable(typeof(TestFile<EcdhTestVector>))]
	[JsonSerializable(typeof(TestFile<MLKemTestVector>))]
	[JsonSerializable(typeof(TestFile<MLKemEncapsTestVector>))]
	[JsonSerializable(typeof(TestFile<MLKemKeyGenTestVector>))]
	[JsonSerializable(typeof(TestFile<MLKemDecapsValidationTestVector>))]
	[JsonSerializable(typeof(GroupFile<KmacTestGroup>))]
	[JsonSerializable(typeof(GroupFile<EcdsaVerifyTestGroup>))]
	[JsonSerializable(typeof(GroupFile<MLDsaVerifyTestGroup>))]
	[JsonSerializable(typeof(GroupFile<MLDsaSignSeedTestGroup>))]
	[JsonSerializable(typeof(GroupFile<MLDsaSignNoSeedTestGroup>))]
	private sealed partial class VectorsJsonContext : JsonSerializerContext;

	private sealed class HexConverter : JsonConverter<byte[]>
	{
		public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
		{
			if (reader is { TokenType: JsonTokenType.String, HasValueSequence: false, ValueIsEscaped: false })
			{
				return Convert.FromHexString(reader.ValueSpan);
			}

			return Convert.FromHexString(reader.GetString() ?? throw new JsonException("Expected a hexadecimal string."));
		}

		public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
		{
			throw new NotSupportedException();
		}
	}
}
