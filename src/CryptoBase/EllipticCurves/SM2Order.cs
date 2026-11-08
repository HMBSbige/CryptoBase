using CryptoBase.Signatures;

namespace CryptoBase.EllipticCurves;

[InlineArray(4)]
internal struct SM2Order : ISM3NonceOrder
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0x53BBF40939D54123UL, 0x7203DF6B21C6052BUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0xAC440BF6C62ABEDDUL, 0x8DFC2094DE39FAD4UL, 0x0000000000000000UL, 0x0000000100000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x901192AF7C114F20UL, 0x3464504ADE6FA2FAUL, 0x620FC84C3AFFE0D4UL, 0x1EB5E412A22B3D3BUL,
	];

	public static ulong NegativeInverse => 0x327F9E8872350975UL;

	public static ReadOnlySpan<byte> NonceTag => "SM2 signature nonce"u8;

	public static ReadOnlySpan<ulong> NonceReciprocal =>
	[
		0x12AC6361F15149A1UL, 0x8DFC2096FA323C01UL, 0x0000000100000001UL, 0x0000000100000001UL,
	];
}
