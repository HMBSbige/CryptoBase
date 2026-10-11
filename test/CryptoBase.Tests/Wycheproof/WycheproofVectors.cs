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
		string path = Path.Combine(VectorsDirectory, fileName);

		if (!File.Exists(path))
		{
			throw new FileNotFoundException($"Wycheproof test vectors '{fileName}' were not found. Run 'git submodule update --init'.", path);
		}

		JsonTypeInfo<TestFile<T>> typeInfo = (JsonTypeInfo<TestFile<T>>)(VectorsJsonContext.Default.GetTypeInfo(typeof(TestFile<T>)) ?? throw new NotSupportedException($"{typeof(T).Name} is not registered in {nameof(VectorsJsonContext)}."));

		using FileStream stream = File.OpenRead(path);
		TestFile<T> file = JsonSerializer.Deserialize(stream, typeInfo) ?? throw new JsonException($"{fileName} is empty.");
		return file.TestGroups.SelectMany(static group => group.Tests);
	}

	private sealed record TestFile<T>(TestGroup<T>[] TestGroups);

	private sealed record TestGroup<T>(T[] Tests);

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
