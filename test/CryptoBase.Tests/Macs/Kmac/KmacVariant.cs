using CryptoBase.Abstractions;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Macs.Kmac;
using CryptoBase.Tests.Hashes.Sha3;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Macs.Kmac;

// The four KMAC classes share no interface that covers their output, so the tests reach them through KmacSubject, which binds each role to the one member that plays it: GetCurrentMac or GetCurrentHash, and GetMacAndReset or GetHashAndReset.
public sealed record KmacVariant(int SecurityStrength, bool Xof)
{
	public static IEnumerable<KmacVariant> All()
	{
		return [.. FixedLength, .. Extendable];
	}

	public static IEnumerable<KmacVariant> FixedLength => [new(128, false), new(256, false)];

	public static IEnumerable<KmacVariant> Extendable => [new(128, true), new(256, true)];

	public int Rate => 200 - SecurityStrength / 4;

	public override string ToString()
	{
		return Xof ? $"KMACXOF{SecurityStrength}" : $"KMAC{SecurityStrength}";
	}

	// Mac or HashData.
	public void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> customization)
	{
		switch (SecurityStrength, Xof)
		{
			case (128, false):
				Kmac128Algorithm.Mac(key, source, destination, customization);
				break;
			case (256, false):
				Kmac256Algorithm.Mac(key, source, destination, customization);
				break;
			case (128, true):
				KmacXof128Algorithm.HashData(key, source, destination, customization);
				break;
			case (256, true):
				KmacXof256Algorithm.HashData(key, source, destination, customization);
				break;
			default:
				throw new NotSupportedException(ToString());
		}
	}

	public byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, int outputLength, ReadOnlySpan<byte> customization)
	{
		byte[] output = new byte[outputLength];
		Compute(key, source, output, customization);
		return output;
	}

	public KmacSubject Create(ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization)
	{
		return (SecurityStrength, Xof) switch
		{
			(128, false) => Subject(Kmac128Algorithm.Create(key, customization)),
			(256, false) => Subject(Kmac256Algorithm.Create(key, customization)),
			(128, true) => Subject(KmacXof128Algorithm.Create(key, customization)),
			(256, true) => Subject(KmacXof256Algorithm.Create(key, customization)),
			_ => throw new NotSupportedException(ToString())
		};
	}

	public byte[] Reference(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, int outputLength, ReadOnlySpan<byte> customization)
	{
		return KeccakReference.Kmac(key, source, Rate, customization, outputLength, Xof);
	}

	private static KmacSubject Subject(Kmac128Algorithm kmac)
	{
		return new KmacSubject(kmac, kmac.GetCurrentMac, kmac.GetMacAndReset, () => Bytes(ref State(kmac)));
	}

	private static KmacSubject Subject(Kmac256Algorithm kmac)
	{
		return new KmacSubject(kmac, kmac.GetCurrentMac, kmac.GetMacAndReset, () => Bytes(ref State(kmac)));
	}

	private static KmacSubject Subject(KmacXof128Algorithm xof)
	{
		return new KmacSubject(xof, xof.GetCurrentHash, xof.GetHashAndReset, () => Bytes(ref State(xof)), xof.Read, () => Subject(xof.Clone()));
	}

	private static KmacSubject Subject(KmacXof256Algorithm xof)
	{
		return new KmacSubject(xof, xof.GetCurrentHash, xof.GetHashAndReset, () => Bytes(ref State(xof)), xof.Read, () => Subject(xof.Clone()));
	}

	private static byte[] Bytes<T>(ref T state) where T : struct
	{
		return MemoryMarshal.AsBytes(new Span<T>(ref state)).ToArray();
	}

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
	private static extern ref KmacState<KeccakRate168> State(Kmac128Algorithm kmac);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
	private static extern ref KmacState<KeccakRate136> State(Kmac256Algorithm kmac);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
	private static extern ref KmacXofState<KeccakRate168> State(KmacXof128Algorithm xof);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
	private static extern ref KmacXofState<KeccakRate136> State(KmacXof256Algorithm xof);
}

public sealed class KmacSubject(IIncrementalAlgorithm kmac, Action<Span<byte>> getCurrent, Action<Span<byte>> getAndReset, Func<byte[]> stateBytes, Action<Span<byte>>? read = null, Func<KmacSubject>? clone = null) : IDisposable
{
	public void Append(ReadOnlySpan<byte> source)
	{
		kmac.Append(source);
	}

	public void GetCurrent(Span<byte> destination)
	{
		getCurrent(destination);
	}

	public void GetAndReset(Span<byte> destination)
	{
		getAndReset(destination);
	}

	public void Reset()
	{
		kmac.Reset();
	}

	public void Dispose()
	{
		((IDisposable)kmac).Dispose();
	}

	// Read and Clone exist on the extendable-output classes only.
	public void Read(Span<byte> destination)
	{
		(read ?? throw new NotSupportedException())(destination);
	}

	public KmacSubject Clone()
	{
		return (clone ?? throw new NotSupportedException())();
	}

	// A copy of the internal state, which holds the key, to check its erasure.
	public byte[] StateBytes()
	{
		return stateBytes();
	}
}
