using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Macs.Kmac;

// KMACXOF of SP 800-185, Sec. 4.3.1, shared by KmacXof128Algorithm and KmacXof256Algorithm, which check disposal before calling in: KMAC with L
// encoded as 0, so that the output is a stream. Reading follows the IXof contract; copies of the state hold the key, so they are erased.
internal struct KmacXofState<TRate> where TRate : IKeccakRate
{
	private CShakeSponge<TRate> _sponge;
	private bool _reading;

	internal void Initialize(ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization)
	{
		KmacState<TRate>.Seed(ref _sponge, key, customization);
		_reading = false;
	}

	internal static void HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> customization)
	{
		KmacState<TRate>.Compute(key, source, customization, 0, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Append(ReadOnlySpan<byte> source)
	{
		ThrowHelper.ThrowIfXofReading(_reading);
		_sponge.Absorb(source);
	}

	internal void Read(Span<byte> destination)
	{
		if (destination.IsEmpty)
		{
			return;
		}

		if (!_reading)
		{
			_sponge.AbsorbRightEncode(0);
			_sponge.Pad();
			_reading = true;
		}

		_sponge.Squeeze(destination);
	}

	internal readonly void GetCurrentHash(Span<byte> destination)
	{
		ThrowHelper.ThrowIfXofReading(_reading);
		_sponge.SqueezeCopy(0, destination);
	}

	internal void GetHashAndReset(Span<byte> destination)
	{
		ThrowHelper.ThrowIfXofReading(_reading);

		KmacState<TRate>.Finish(ref _sponge, 0, destination);
		_sponge.Reset();
	}

	internal void Reset()
	{
		_sponge.Reset();
		_reading = false;
	}

	internal void ZeroMemory()
	{
		_sponge.ZeroMemory();
		_reading = false;
	}
}
