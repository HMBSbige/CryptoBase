using CryptoBase.Tests.Hashes.Blake2b;
using System.Buffers.Binary;

namespace CryptoBase.Tests.Kdf.Argon2;

internal static class Argon2Reference
{
	public const int BlockWords = 128;

	private const int SyncPoints = 4;
	private const int Version = 0x13;
	private const int TypeArgon2id = 2;

	public static byte[] Argon2id(byte[] password, byte[] salt, byte[] secret, byte[] associatedData, int memorySize, int iterations, int parallelism, int tagLength)
	{
		byte[] h0 = Blake2bReference.Hash([.. Le32(parallelism), .. Le32(tagLength), .. Le32(memorySize), .. Le32(iterations), .. Le32(Version), .. Le32(TypeArgon2id), .. Le32(password.Length), .. password, .. Le32(salt.Length), .. salt, .. Le32(secret.Length), .. secret, .. Le32(associatedData.Length), .. associatedData], 64);

		int memoryBlocks = 4 * parallelism * (memorySize / (4 * parallelism));
		int laneLength = memoryBlocks / parallelism;
		int segmentLength = laneLength / SyncPoints;
		ulong[][][] b = new ulong[parallelism][][];

		for (int lane = 0; lane < parallelism; ++lane)
		{
			b[lane] = new ulong[laneLength][];
			b[lane][0] = ToWords(HPrime([.. h0, .. Le32(0), .. Le32(lane)], 1024));
			b[lane][1] = ToWords(HPrime([.. h0, .. Le32(1), .. Le32(lane)], 1024));
		}

		for (int pass = 0; pass < iterations; ++pass)
		{
			for (int slice = 0; slice < SyncPoints; ++slice)
			{
				for (int lane = 0; lane < parallelism; ++lane)
				{
					ulong[] addresses = [];
					int addressCounter = 0;

					for (int k = 0; k < segmentLength; ++k)
					{
						int j = slice * segmentLength + k;

						if (pass is 0 && j < 2)
						{
							continue;
						}

						int previous = j is 0 ? laneLength - 1 : j - 1;
						ulong pseudoRandom;

						if (pass is 0 && slice < SyncPoints / 2)
						{
							if (addressCounter != k / BlockWords + 1)
							{
								addressCounter = k / BlockWords + 1;
								ulong[] input = new ulong[BlockWords];
								input[0] = (ulong)pass;
								input[1] = (ulong)lane;
								input[2] = (ulong)slice;
								input[3] = (ulong)memoryBlocks;
								input[4] = (ulong)iterations;
								input[5] = TypeArgon2id;
								input[6] = (ulong)addressCounter;
								ulong[] zero = new ulong[BlockWords];
								addresses = G(zero, G(zero, input));
							}

							pseudoRandom = addresses[k % BlockWords];
						}
						else
						{
							pseudoRandom = b[lane][previous][0];
						}

						uint j1 = (uint)pseudoRandom;
						uint j2 = (uint)(pseudoRandom >> 32);
						int referenceLane = pass is 0 && slice is 0 ? lane : (int)(j2 % (uint)parallelism);
						List<int> w = ReferenceSet(pass, slice, k, segmentLength, referenceLane == lane);
						ulong x = (ulong)j1 * j1 >> 32;
						ulong y = (ulong)w.Count * x >> 32;
						int z = w[(int)((ulong)w.Count - 1 - y)];

						ulong[] next = G(b[lane][previous], b[referenceLane][z]);

						if (pass is not 0)
						{
							for (int i = 0; i < BlockWords; ++i)
							{
								next[i] ^= b[lane][j][i];
							}
						}

						b[lane][j] = next;
					}
				}
			}
		}

		ulong[] c = new ulong[BlockWords];

		for (int lane = 0; lane < parallelism; ++lane)
		{
			for (int i = 0; i < BlockWords; ++i)
			{
				c[i] ^= b[lane][laneLength - 1][i];
			}
		}

		return HPrime(ToBytes(c), tagLength);
	}

	public static ulong[] G(ulong[] x, ulong[] y)
	{
		ulong[] r = new ulong[BlockWords];

		for (int i = 0; i < BlockWords; ++i)
		{
			r[i] = x[i] ^ y[i];
		}

		ulong[] z = (ulong[])r.Clone();

		for (int row = 0; row < 8; ++row)
		{
			P(z, [8 * row, 8 * row + 1, 8 * row + 2, 8 * row + 3, 8 * row + 4, 8 * row + 5, 8 * row + 6, 8 * row + 7]);
		}

		for (int column = 0; column < 8; ++column)
		{
			P(z, [column, column + 8, column + 16, column + 24, column + 32, column + 40, column + 48, column + 56]);
		}

		for (int i = 0; i < BlockWords; ++i)
		{
			z[i] ^= r[i];
		}

		return z;
	}

	private static byte[] HPrime(byte[] input, int length)
	{
		byte[] prefixed = [.. Le32(length), .. input];

		if (length <= 64)
		{
			return Blake2bReference.Hash(prefixed, length);
		}

		int r = (length + 31) / 32 - 2;
		byte[] output = new byte[length];
		byte[] v = Blake2bReference.Hash(prefixed, 64);
		v.AsSpan(0, 32).CopyTo(output);

		for (int i = 1; i < r; ++i)
		{
			v = Blake2bReference.Hash(v, 64);
			v.AsSpan(0, 32).CopyTo(output.AsSpan(32 * i));
		}

		Blake2bReference.Hash(v, length - 32 * r).CopyTo(output.AsSpan(32 * r));
		return output;
	}

	private static List<int> ReferenceSet(int pass, int slice, int k, int segmentLength, bool sameLane)
	{
		List<int> w = [];
		int finishedSegments = pass is 0 ? slice : SyncPoints - 1;

		for (int segment = slice - finishedSegments; segment < slice; ++segment)
		{
			int start = (segment + SyncPoints) % SyncPoints * segmentLength;

			for (int i = 0; i < segmentLength; ++i)
			{
				w.Add(start + i);
			}
		}

		if (sameLane)
		{
			for (int i = 0; i < k - 1; ++i)
			{
				w.Add(slice * segmentLength + i);
			}
		}

		if (k is 0)
		{
			w.RemoveAt(w.Count - 1);
		}

		return w;
	}

	private static void P(ulong[] block, int[] registers)
	{
		ulong[] v = new ulong[16];

		for (int i = 0; i < 8; ++i)
		{
			v[2 * i] = block[2 * registers[i]];
			v[2 * i + 1] = block[2 * registers[i] + 1];
		}

		GB(v, 0, 4, 8, 12);
		GB(v, 1, 5, 9, 13);
		GB(v, 2, 6, 10, 14);
		GB(v, 3, 7, 11, 15);
		GB(v, 0, 5, 10, 15);
		GB(v, 1, 6, 11, 12);
		GB(v, 2, 7, 8, 13);
		GB(v, 3, 4, 9, 14);

		for (int i = 0; i < 8; ++i)
		{
			block[2 * registers[i]] = v[2 * i];
			block[2 * registers[i] + 1] = v[2 * i + 1];
		}
	}

	private static void GB(ulong[] v, int a, int b, int c, int d)
	{
		v[a] = v[a] + v[b] + 2 * (ulong)(uint)v[a] * (uint)v[b];
		v[d] = ulong.RotateRight(v[d] ^ v[a], 32);
		v[c] = v[c] + v[d] + 2 * (ulong)(uint)v[c] * (uint)v[d];
		v[b] = ulong.RotateRight(v[b] ^ v[c], 24);
		v[a] = v[a] + v[b] + 2 * (ulong)(uint)v[a] * (uint)v[b];
		v[d] = ulong.RotateRight(v[d] ^ v[a], 16);
		v[c] = v[c] + v[d] + 2 * (ulong)(uint)v[c] * (uint)v[d];
		v[b] = ulong.RotateRight(v[b] ^ v[c], 63);
	}

	private static ulong[] ToWords(byte[] bytes)
	{
		ulong[] words = new ulong[bytes.Length / sizeof(ulong)];

		for (int i = 0; i < words.Length; ++i)
		{
			words[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i * sizeof(ulong)));
		}

		return words;
	}

	private static byte[] ToBytes(ulong[] words)
	{
		byte[] bytes = new byte[words.Length * sizeof(ulong)];

		for (int i = 0; i < words.Length; ++i)
		{
			BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(i * sizeof(ulong)), words[i]);
		}

		return bytes;
	}

	private static byte[] Le32(int value)
	{
		byte[] bytes = new byte[sizeof(uint)];
		BinaryPrimitives.WriteUInt32LittleEndian(bytes, (uint)value);
		return bytes;
	}
}
