namespace CryptoBase.EllipticCurves;

[InlineArray(6)]
internal struct P384Order : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 6;

	public static int ByteLength => 48;

	public static int BitLength => 384;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xECEC196ACCC52973UL, 0x581A0DB248B0A77AUL, 0xC7634D81F4372DDFUL, 0xFFFFFFFFFFFFFFFFUL,
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x1313E695333AD68DUL, 0xA7E5F24DB74F5885UL, 0x389CB27E0BC8D220UL, 0x0000000000000000UL,
		0x0000000000000000UL, 0x0000000000000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x2D319B2419B409A9UL, 0xFF3D81E5DF1AA419UL, 0xBC3E483AFCB82947UL, 0xD40D49174AAB1CC5UL,
		0x3FB05B7A28266895UL, 0x0C84EE012B39BF21UL,
	];

	public static ulong NegativeInverse => 0x6ED46089E88FDC45UL;
}
