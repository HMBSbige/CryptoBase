namespace CryptoBase.Kdf.Argon2;

[InlineArray(QWordCount)]
internal struct Argon2Block
{
	internal const int QWordCount = 128;
	internal const int SizeInBytes = QWordCount * sizeof(ulong);

	private ulong _element;
}
