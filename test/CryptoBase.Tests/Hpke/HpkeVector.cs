using CryptoBase.Hpke;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoBase.Tests.Hpke;

// A vector of Vectors/hpke-test-vectors.json, whose README gives the sources. A vector without kdf_id has only KEM values, and one without ikmR has only a key schedule.
public sealed record HpkeVector
{
	public required string Source { get; init; }

	public int Mode { get; init; }

	[JsonPropertyName("kem_id")]
	public required ushort KemId { get; init; }

	[JsonPropertyName("kdf_id")]
	public HpkeKdf? Kdf { get; init; }

	[JsonPropertyName("aead_id")]
	public HpkeAead? Aead { get; init; }

	public byte[] Info { get; init; } = [];

	public byte[]? IkmE { get; init; }

	public byte[]? SkEm { get; init; }

	public byte[]? PkEm { get; init; }

	public byte[]? IkmR { get; init; }

	public byte[]? SkRm { get; init; }

	public byte[]? PkRm { get; init; }

	public byte[]? IkmS { get; init; }

	public byte[]? SkSm { get; init; }

	public byte[]? PkSm { get; init; }

	public byte[] Psk { get; init; } = [];

	[JsonPropertyName("psk_id")]
	public byte[] PskId { get; init; } = [];

	public byte[]? Enc { get; init; }

	[JsonPropertyName("shared_secret")]
	public required byte[] SharedSecret { get; init; }

	public HpkeEncryption[] Encryptions { get; init; } = [];

	public HpkeExport[] Exports { get; init; } = [];

	public bool IsAuthenticated => Mode is 2 or 3;

	public bool HasPsk => Mode is 1 or 3;

	public override string ToString()
	{
		return Kdf is null ? $"{Source}, KEM 0x{KemId:X4}" : $"{Source}, mode {Mode}, KEM 0x{KemId:X4}, {Kdf}, {Aead}";
	}
}

public sealed record HpkeEncryption(int Seq, byte[] Pt, byte[] Aad, byte[] Ct);

public sealed record HpkeExport([property: JsonPropertyName("exporter_context")] byte[] ExporterContext, int L, [property: JsonPropertyName("exported_value")] byte[] ExportedValue);

internal static partial class HpkeVectors
{
	private static readonly HpkeVector[] All = Load();

	// Vectors with a DHKEM of this library and every value of the KEM and the key schedule.
	public static IEnumerable<HpkeVector> Full()
	{
		return All.Where(static vector => vector is { IkmR: not null, Kdf: not null });
	}

	public static IEnumerable<HpkeVector> KemOnly()
	{
		return All.Where(static vector => vector.Kdf is null);
	}

	public static IEnumerable<HpkeVector> WithKeySchedule()
	{
		return All.Where(static vector => vector.Kdf is not null);
	}

	private static HpkeVector[] Load()
	{
		const string fileName = "hpke-test-vectors.json";
		using Stream stream = typeof(HpkeVectors).Assembly.GetManifestResourceStream(fileName) ?? throw new FileNotFoundException($"HPKE test vectors '{fileName}' are not embedded.", fileName);
		return JsonSerializer.Deserialize(stream, HpkeVectorsJsonContext.Default.HpkeVectorArray) ?? throw new JsonException($"{fileName} is empty.");
	}

	[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, RespectNullableAnnotations = true, Converters = [typeof(HexConverter)])]
	[JsonSerializable(typeof(HpkeVector[]))]
	private sealed partial class HpkeVectorsJsonContext : JsonSerializerContext;

	private sealed class HexConverter : JsonConverter<byte[]>
	{
		public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
		{
			return Convert.FromHexString(reader.GetString() ?? throw new JsonException("Expected a hexadecimal string."));
		}

		public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
		{
			throw new NotSupportedException();
		}
	}
}
