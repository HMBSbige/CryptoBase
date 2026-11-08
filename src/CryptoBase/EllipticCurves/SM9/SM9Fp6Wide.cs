namespace CryptoBase.EllipticCurves.SM9;

// An element C0 + C1·v + C2·v² of Fp6 as sums of products before reduction, with the rules of SM9Fp2Wide. The operations are not inlined: each touches sixty columns, and inlined into the operations of Fp12 they would leave those too long for the op cache.
internal struct SM9Fp6Wide
{
	internal SM9Fp2Wide C0;
	internal SM9Fp2Wide C1;
	internal SM9Fp2Wide C2;

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Subtract(in SM9Fp6Wide left, in SM9Fp6Wide right, out SM9Fp6Wide result)
	{
		SM9Fp2Wide.Subtract(in left.C0, in right.C0, out result.C0);
		SM9Fp2Wide.Subtract(in left.C1, in right.C1, out result.C1);
		SM9Fp2Wide.Subtract(in left.C2, in right.C2, out result.C2);
	}

	// left + v·right = (left0 + u·right2) + (left1 + right0)·v + (left2 + right1)·v².
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void AddTimesV(in SM9Fp6Wide left, in SM9Fp6Wide right, out SM9Fp6Wide result)
	{
		SM9Fp2Wide r0 = right.C0;
		SM9Fp2Wide r1 = right.C1;
		SM9Fp2Wide.AddTimesU(in left.C0, in right.C2, out result.C0);
		SM9Fp2Wide.Add(in left.C1, in r0, out result.C1);
		SM9Fp2Wide.Add(in left.C2, in r1, out result.C2);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Normalize(ref SM9Fp6Wide value)
	{
		SM9Fp2Wide.Normalize(ref value.C0);
		SM9Fp2Wide.Normalize(ref value.C1);
		SM9Fp2Wide.Normalize(ref value.C2);
	}

	// Reduces the six coefficients, each in (−128p², 342p²).
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Reduce(in SM9Fp6Wide value, out SM9Fp6 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2Wide.Reduce(in value.C0, out result.C0);
		SM9Fp2Wide.Reduce(in value.C1, out result.C1);
		SM9Fp2Wide.Reduce(in value.C2, out result.C2);
	}
}
