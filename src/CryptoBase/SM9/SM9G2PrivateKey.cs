using CryptoBase.EllipticCurves.SM9;

namespace CryptoBase.SM9;

// The private key de of G2 of a user of an encryption master key, with the lines of the Miller loop for it, which the first pairing builds, so that each later pairing e(P, de) costs less. The lines are as secret as de: threads that pair at once may each build them, but only the first to finish publishes them and the others erase theirs, and Dispose erases de and the lines.
internal sealed class SM9G2PrivateKey : IDisposable
{
	private SM9AffinePoint<SM9Fp2> _point;
	private SM9PairingLines? _lines;

	// For a point of G2.
	internal SM9G2PrivateKey(in SM9AffinePoint<SM9Fp2> point)
	{
		_point = point;
	}

	internal ref readonly SM9AffinePoint<SM9Fp2> Point => ref _point;

	// e(P, de) for a public P of G1, as the ciphertexts, the ephemeral keys of peers and the user public keys are: the time depends on P, but neither it nor the addresses depend on de.
	internal void PairVariableTime(in SM9AffinePoint<SM9Fp> p, out SM9Fp12 result)
	{
		(_lines ?? PublishLines()).PairVariableTime(in p, out result);
	}

	public void Dispose()
	{
		_point.ZeroMemory();
		Interlocked.Exchange(ref _lines, null)?.Dispose();
	}

	private SM9PairingLines PublishLines()
	{
		SM9PairingLines lines = new(in _point);

		if (Interlocked.CompareExchange(ref _lines, lines, null) is { } published)
		{
			lines.Dispose();
			return published;
		}

		return lines;
	}
}
