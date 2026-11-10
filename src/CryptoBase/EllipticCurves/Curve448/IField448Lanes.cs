namespace CryptoBase.EllipticCurves.Curve448;

// Elements of the field in lanes, each in sixteen limbs of radix 2^28, as the vector fields hold them.
internal interface IField448Lanes<TSelf> where TSelf : struct, IField448Lanes<TSelf>
{
	static abstract ulong Limb(in TSelf value, int limb, int lane);
}
