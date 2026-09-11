using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;

namespace CryptoBase.Benchmark.SymmetricCryptos.BlockCryptos;

internal static class BlockCipherBenchmarkUtils
{
	public static void Transform<TCipher>(TCipher cipher, bool isDecrypt, ReadOnlySpan<byte> source, Span<byte> destination) where TCipher : IBlock16Cipher<TCipher>
	{
		int offset = 0;
		BlockCipherHardwareAcceleration acceleration = TCipher.HardwareAcceleration;

		if (acceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512))
		{
			while (source.Length - offset >= 512)
			{
				ref readonly VectorBuffer512 input = ref source.Slice(offset).AsVectorBuffer512();
				ref VectorBuffer512 output = ref destination.Slice(offset).AsVectorBuffer512();
				output = isDecrypt ? cipher.DecryptV512(input) : cipher.EncryptV512(input);
				offset += 512;
			}
		}

		if (acceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V512))
		{
			while (source.Length - offset >= 256)
			{
				ref readonly VectorBuffer256 input = ref source.Slice(offset).AsVectorBuffer256();
				ref VectorBuffer256 output = ref destination.Slice(offset).AsVectorBuffer256();
				output = isDecrypt ? cipher.DecryptV512(input) : cipher.EncryptV512(input);
				offset += 256;
			}
		}
		else if (acceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V256))
		{
			while (source.Length - offset >= 256)
			{
				ref readonly VectorBuffer256 input = ref source.Slice(offset).AsVectorBuffer256();
				ref VectorBuffer256 output = ref destination.Slice(offset).AsVectorBuffer256();
				output = isDecrypt ? cipher.DecryptV256(input) : cipher.EncryptV256(input);
				offset += 256;
			}
		}

		if (acceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
		{
			while (source.Length - offset >= 128)
			{
				ref readonly VectorBuffer128 input = ref source.Slice(offset).AsVectorBuffer128();
				ref VectorBuffer128 output = ref destination.Slice(offset).AsVectorBuffer128();
				output = isDecrypt ? cipher.DecryptV256(input) : cipher.EncryptV256(input);
				offset += 128;
			}
		}

		while (source.Length - offset >= 128)
		{
			ref readonly VectorBuffer128 input = ref source.Slice(offset).AsVectorBuffer128();
			ref VectorBuffer128 output = ref destination.Slice(offset).AsVectorBuffer128();
			output = isDecrypt ? cipher.Decrypt(input) : cipher.Encrypt(input);
			offset += 128;
		}

		if (source.Length - offset >= 64)
		{
			ref readonly VectorBuffer64 input = ref source.Slice(offset).AsVectorBuffer64();
			ref VectorBuffer64 output = ref destination.Slice(offset).AsVectorBuffer64();
			output = isDecrypt ? cipher.Decrypt(input) : cipher.Encrypt(input);
			offset += 64;
		}

		if (source.Length - offset >= 32)
		{
			ref readonly VectorBuffer32 input = ref source.Slice(offset).AsVectorBuffer32();
			ref VectorBuffer32 output = ref destination.Slice(offset).AsVectorBuffer32();
			output = isDecrypt ? cipher.Decrypt(input) : cipher.Encrypt(input);
			offset += 32;
		}

		if (source.Length - offset >= 16)
		{
			VectorBuffer16 input = source.Slice(offset).AsVectorBuffer16();
			ref VectorBuffer16 output = ref destination.Slice(offset).AsVectorBuffer16();
			output = isDecrypt ? cipher.Decrypt(input) : cipher.Encrypt(input);
		}
	}
}
