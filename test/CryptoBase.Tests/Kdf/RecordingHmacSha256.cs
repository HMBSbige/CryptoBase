using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Macs.Hmac;

namespace CryptoBase.Tests.Kdf;

/// <summary>
/// HMAC-SHA256 that counts its calls into the <see cref="MacCallCounts" /> that the latest <see cref="Record" /> in the current async flow returned, so that
/// tests running in parallel each see only their own calls.
/// </summary>
internal sealed class RecordingHmacSha256 : IMacAlgorithm<RecordingHmacSha256>
{
	private static readonly AsyncLocal<MacCallCounts?> CurrentCounts = new();

	private readonly HmacAlgorithm<Sha256HashAlgorithm> _hmac;

	private RecordingHmacSha256(HmacAlgorithm<Sha256HashAlgorithm> hmac)
	{
		_hmac = hmac;
	}

	public static int MacLength => HmacAlgorithm<Sha256HashAlgorithm>.MacLength;

	private static MacCallCounts Counts => CurrentCounts.Value ?? throw new InvalidOperationException($"Call {nameof(Record)} before using {nameof(RecordingHmacSha256)}.");

	/// <summary>
	/// Starts counting the calls made in the current async flow.
	/// </summary>
	public static MacCallCounts Record()
	{
		MacCallCounts counts = new();
		CurrentCounts.Value = counts;
		return counts;
	}

	public static RecordingHmacSha256 Create(ReadOnlySpan<byte> key)
	{
		++Counts.Create;
		return new RecordingHmacSha256(HmacAlgorithm<Sha256HashAlgorithm>.Create(key));
	}

	public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		++Counts.Mac;
		return HmacAlgorithm<Sha256HashAlgorithm>.Mac(key, source, destination);
	}

	public void Append(ReadOnlySpan<byte> source)
	{
		++Counts.Append;
		_hmac.Append(source);
	}

	public void Reset()
	{
		++Counts.Reset;
		_hmac.Reset();
	}

	public int GetCurrentMac(Span<byte> destination)
	{
		++Counts.GetCurrentMac;
		return _hmac.GetCurrentMac(destination);
	}

	public int GetMacAndReset(Span<byte> destination)
	{
		++Counts.GetMacAndReset;
		return _hmac.GetMacAndReset(destination);
	}

	public void Dispose()
	{
		++Counts.Dispose;
		_hmac.Dispose();
	}
}

/// <summary>
/// The calls that <see cref="RecordingHmacSha256" /> received, compared by value.
/// </summary>
internal sealed record MacCallCounts
{
	public int Mac { get; set; }

	public int Create { get; set; }

	public int Append { get; set; }

	public int Reset { get; set; }

	public int GetCurrentMac { get; set; }

	public int GetMacAndReset { get; set; }

	public int Dispose { get; set; }
}
