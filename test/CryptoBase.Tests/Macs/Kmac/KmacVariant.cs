using CryptoBase.Hashes.Sha3;
using CryptoBase.Macs.Kmac;
using CryptoBase.Tests.Hashes.Sha3;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Macs.Kmac;

// The four KMAC classes share no interface that covers their output, so the tests reach them through KmacSubject, whose members each forward to
// the one member of the same role: GetCurrentMac or GetCurrentHash, and GetMacAndReset or GetHashAndReset.
public sealed record KmacVariant(int SecurityStrength, bool Xof)
{
	public static IEnumerable<KmacVariant> All => [.. FixedLength, .. Extendable];

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
			(128, false) => new KmacSubject.Fixed128(Kmac128Algorithm.Create(key, customization)),
			(256, false) => new KmacSubject.Fixed256(Kmac256Algorithm.Create(key, customization)),
			(128, true) => new KmacSubject.Xof128(KmacXof128Algorithm.Create(key, customization)),
			(256, true) => new KmacSubject.Xof256(KmacXof256Algorithm.Create(key, customization)),
			_ => throw new NotSupportedException(ToString())
		};
	}

	public byte[] Reference(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, int outputLength, ReadOnlySpan<byte> customization)
	{
		return KeccakReference.Kmac(key, source, Rate, customization, outputLength, Xof);
	}
}

public abstract class KmacSubject : IDisposable
{
	private KmacSubject() { }

	public abstract void Append(ReadOnlySpan<byte> source);

	public abstract void GetCurrent(Span<byte> destination);

	public abstract void GetAndReset(Span<byte> destination);

	public abstract void Reset();

	public abstract void Dispose();

	// Read and Clone exist on the extendable-output classes only.
	public virtual void Read(Span<byte> destination)
	{
		throw new NotSupportedException();
	}

	public virtual KmacSubject Clone()
	{
		throw new NotSupportedException();
	}

	// A copy of the internal state, which holds the key, to check its erasure.
	public abstract byte[] StateBytes();

	private static byte[] Bytes<T>(ref T state) where T : struct
	{
		return MemoryMarshal.AsBytes(new Span<T>(ref state)).ToArray();
	}

	public sealed class Fixed128(Kmac128Algorithm kmac) : KmacSubject
	{
		public override void Append(ReadOnlySpan<byte> source)
		{
			kmac.Append(source);
		}

		public override void GetCurrent(Span<byte> destination)
		{
			kmac.GetCurrentMac(destination);
		}

		public override void GetAndReset(Span<byte> destination)
		{
			kmac.GetMacAndReset(destination);
		}

		public override void Reset()
		{
			kmac.Reset();
		}

		public override void Dispose()
		{
			kmac.Dispose();
		}

		public override byte[] StateBytes()
		{
			return Bytes(ref State(kmac));
		}

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
		private static extern ref KmacState<KeccakRate168> State(Kmac128Algorithm kmac);
	}

	public sealed class Fixed256(Kmac256Algorithm kmac) : KmacSubject
	{
		public override void Append(ReadOnlySpan<byte> source)
		{
			kmac.Append(source);
		}

		public override void GetCurrent(Span<byte> destination)
		{
			kmac.GetCurrentMac(destination);
		}

		public override void GetAndReset(Span<byte> destination)
		{
			kmac.GetMacAndReset(destination);
		}

		public override void Reset()
		{
			kmac.Reset();
		}

		public override void Dispose()
		{
			kmac.Dispose();
		}

		public override byte[] StateBytes()
		{
			return Bytes(ref State(kmac));
		}

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
		private static extern ref KmacState<KeccakRate136> State(Kmac256Algorithm kmac);
	}

	public sealed class Xof128(KmacXof128Algorithm xof) : KmacSubject
	{
		public override void Append(ReadOnlySpan<byte> source)
		{
			xof.Append(source);
		}

		public override void GetCurrent(Span<byte> destination)
		{
			xof.GetCurrentHash(destination);
		}

		public override void GetAndReset(Span<byte> destination)
		{
			xof.GetHashAndReset(destination);
		}

		public override void Reset()
		{
			xof.Reset();
		}

		public override void Dispose()
		{
			xof.Dispose();
		}

		public override void Read(Span<byte> destination)
		{
			xof.Read(destination);
		}

		public override KmacSubject Clone()
		{
			return new Xof128(xof.Clone());
		}

		public override byte[] StateBytes()
		{
			return Bytes(ref State(xof));
		}

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
		private static extern ref KmacXofState<KeccakRate168> State(KmacXof128Algorithm xof);
	}

	public sealed class Xof256(KmacXof256Algorithm xof) : KmacSubject
	{
		public override void Append(ReadOnlySpan<byte> source)
		{
			xof.Append(source);
		}

		public override void GetCurrent(Span<byte> destination)
		{
			xof.GetCurrentHash(destination);
		}

		public override void GetAndReset(Span<byte> destination)
		{
			xof.GetHashAndReset(destination);
		}

		public override void Reset()
		{
			xof.Reset();
		}

		public override void Dispose()
		{
			xof.Dispose();
		}

		public override void Read(Span<byte> destination)
		{
			xof.Read(destination);
		}

		public override KmacSubject Clone()
		{
			return new Xof256(xof.Clone());
		}

		public override byte[] StateBytes()
		{
			return Bytes(ref State(xof));
		}

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
		private static extern ref KmacXofState<KeccakRate136> State(KmacXof256Algorithm xof);
	}
}
