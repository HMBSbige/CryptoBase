namespace CryptoBase.Macs.Poly1305;

// Radix 2^26 representation.
internal struct Poly1305Power
{
	internal uint Limb0;
	internal uint Limb1;
	internal uint Limb2;
	internal uint Limb3;
	internal uint Limb4;

	internal Poly1305Power(uint limb0, uint limb1, uint limb2, uint limb3, uint limb4)
	{
		Limb0 = limb0;
		Limb1 = limb1;
		Limb2 = limb2;
		Limb3 = limb3;
		Limb4 = limb4;
	}
}
