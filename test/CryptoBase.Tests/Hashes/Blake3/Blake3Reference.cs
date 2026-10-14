using System.Buffers.Binary;
using System.Numerics;

namespace CryptoBase.Tests.Hashes.Blake3;

internal sealed class Blake3Reference
{
	public const int KeyLength = 32;
	public const int OutLength = 32;
	public const int BlockLength = 64;
	public const int ChunkLength = 1024;

	public const uint ChunkStart = 1 << 0;
	public const uint ChunkEnd = 1 << 1;
	public const uint Parent = 1 << 2;
	public const uint Root = 1 << 3;
	public const uint KeyedHash = 1 << 4;
	public const uint DeriveKeyContext = 1 << 5;
	public const uint DeriveKeyMaterial = 1 << 6;

	private static readonly uint[] IVWords = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

	private static readonly int[] MessagePermutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

	private readonly uint[] _keyWords;
	private readonly uint _flags;
	private readonly Stack<uint[]> _cvStack = [];
	private ChunkState _chunkState;

	public static uint[] IV => (uint[])IVWords.Clone();

	private Blake3Reference(uint[] keyWords, uint flags)
	{
		_keyWords = keyWords;
		_flags = flags;
		_chunkState = new ChunkState(keyWords, 0, flags);
	}

	public static Blake3Reference Create()
	{
		return new Blake3Reference(IV, 0);
	}

	public static Blake3Reference CreateKeyed(ReadOnlySpan<byte> key)
	{
		return new Blake3Reference(WordsFromLittleEndianBytes(key), KeyedHash);
	}

	public static Blake3Reference CreateDeriveKey(ReadOnlySpan<byte> context)
	{
		Blake3Reference contextHasher = new(IV, DeriveKeyContext);
		contextHasher.Update(context);
		byte[] contextKey = new byte[KeyLength];
		contextHasher.Finalize(contextKey);
		return new Blake3Reference(WordsFromLittleEndianBytes(contextKey), DeriveKeyMaterial);
	}

	public void Update(ReadOnlySpan<byte> input)
	{
		while (!input.IsEmpty)
		{
			if (_chunkState.Length is ChunkLength)
			{
				uint[] chunkCv = _chunkState.CreateOutput().ChainingValue();
				ulong totalChunks = _chunkState.ChunkCounter + 1;
				AddChunkChainingValue(chunkCv, totalChunks);
				_chunkState = new ChunkState(_keyWords, totalChunks, _flags);
			}

			int take = Math.Min(ChunkLength - _chunkState.Length, input.Length);
			_chunkState.Update(input.Slice(0, take));
			input = input.Slice(take);
		}
	}

	public void Finalize(Span<byte> output, ulong position = 0)
	{
		Output node = _chunkState.CreateOutput();

		foreach (uint[] leftCv in _cvStack)
		{
			node = ParentOutput(leftCv, node.ChainingValue(), _keyWords, _flags);
		}

		node.RootOutputBytes(output, position);
	}

	public static byte[] SubtreeChildren(ReadOnlySpan<byte> input, uint[] keyWords, ulong chunkCounter, uint flags)
	{
		int leftLength = ChunkLength;

		while (2 * leftLength < input.Length)
		{
			leftLength *= 2;
		}

		byte[] children = new byte[2 * OutLength];
		SubtreeChainingValue(input.Slice(0, leftLength), keyWords, chunkCounter, flags).CopyTo(children, 0);
		SubtreeChainingValue(input.Slice(leftLength), keyWords, chunkCounter + (ulong)(leftLength / ChunkLength), flags).CopyTo(children, OutLength);
		return children;
	}

	public static byte[] ChunkChainingValue(ReadOnlySpan<byte> chunk, uint[] keyWords, ulong chunkCounter, uint flags)
	{
		return LittleEndianBytes(ChunkOutput(chunk, keyWords, chunkCounter, flags).ChainingValue());
	}

	public static byte[] ParentChainingValue(ReadOnlySpan<byte> children, uint[] keyWords, uint flags)
	{
		return LittleEndianBytes(ParentOutput(children, keyWords, flags).ChainingValue());
	}

	public static byte[] CompressBytes(uint[] chainingValue, ReadOnlySpan<byte> block, ulong counter, uint blockLength, uint flags)
	{
		return LittleEndianBytes(Compress(chainingValue, WordsFromLittleEndianBytes(block), counter, blockLength, flags));
	}

	public static uint[] WordsFromLittleEndianBytes(ReadOnlySpan<byte> bytes)
	{
		uint[] words = new uint[bytes.Length / sizeof(uint)];

		for (int i = 0; i < words.Length; ++i)
		{
			words[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i * sizeof(uint)));
		}

		return words;
	}

	private static byte[] LittleEndianBytes(ReadOnlySpan<uint> words)
	{
		byte[] bytes = new byte[words.Length * sizeof(uint)];

		for (int i = 0; i < words.Length; ++i)
		{
			BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * sizeof(uint)), words[i]);
		}

		return bytes;
	}

	private static byte[] SubtreeChainingValue(ReadOnlySpan<byte> input, uint[] keyWords, ulong chunkCounter, uint flags)
	{
		return input.Length <= ChunkLength ? ChunkChainingValue(input, keyWords, chunkCounter, flags) : ParentChainingValue(SubtreeChildren(input, keyWords, chunkCounter, flags), keyWords, flags);
	}

	private static Output ChunkOutput(ReadOnlySpan<byte> chunk, uint[] keyWords, ulong chunkCounter, uint flags)
	{
		ChunkState state = new(keyWords, chunkCounter, flags);
		state.Update(chunk);
		return state.CreateOutput();
	}

	private void AddChunkChainingValue(uint[] newCv, ulong totalChunks)
	{
		while ((totalChunks & 1) is 0)
		{
			newCv = ParentOutput(_cvStack.Pop(), newCv, _keyWords, _flags).ChainingValue();
			totalChunks >>= 1;
		}

		_cvStack.Push(newCv);
	}

	private static Output ParentOutput(uint[] leftChildCv, uint[] rightChildCv, uint[] keyWords, uint flags)
	{
		return new Output(keyWords, [.. leftChildCv, .. rightChildCv], 0, BlockLength, Parent | flags);
	}

	private static Output ParentOutput(ReadOnlySpan<byte> children, uint[] keyWords, uint flags)
	{
		return new Output(keyWords, WordsFromLittleEndianBytes(children), 0, BlockLength, Parent | flags);
	}

	private static uint[] Compress(uint[] chainingValue, uint[] blockWords, ulong counter, uint blockLength, uint flags)
	{
		uint[] state =
		[
			chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
			chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
			IVWords[0], IVWords[1], IVWords[2], IVWords[3],
			(uint)counter, (uint)(counter >> 32), blockLength, flags
		];
		uint[] block = (uint[])blockWords.Clone();

		for (int round = 0; round < 7; ++round)
		{
			if (round is not 0)
			{
				Permute(block);
			}

			Round(state, block);
		}

		for (int i = 0; i < 8; ++i)
		{
			state[i] ^= state[i + 8];
			state[i + 8] ^= chainingValue[i];
		}

		return state;
	}

	private static void Round(uint[] state, uint[] m)
	{
		G(state, 0, 4, 8, 12, m[0], m[1]);
		G(state, 1, 5, 9, 13, m[2], m[3]);
		G(state, 2, 6, 10, 14, m[4], m[5]);
		G(state, 3, 7, 11, 15, m[6], m[7]);
		G(state, 0, 5, 10, 15, m[8], m[9]);
		G(state, 1, 6, 11, 12, m[10], m[11]);
		G(state, 2, 7, 8, 13, m[12], m[13]);
		G(state, 3, 4, 9, 14, m[14], m[15]);
	}

	private static void G(uint[] state, int a, int b, int c, int d, uint mx, uint my)
	{
		state[a] = state[a] + state[b] + mx;
		state[d] = BitOperations.RotateRight(state[d] ^ state[a], 16);
		state[c] = state[c] + state[d];
		state[b] = BitOperations.RotateRight(state[b] ^ state[c], 12);
		state[a] = state[a] + state[b] + my;
		state[d] = BitOperations.RotateRight(state[d] ^ state[a], 8);
		state[c] = state[c] + state[d];
		state[b] = BitOperations.RotateRight(state[b] ^ state[c], 7);
	}

	private static void Permute(uint[] m)
	{
		uint[] original = (uint[])m.Clone();

		for (int i = 0; i < m.Length; ++i)
		{
			m[i] = original[MessagePermutation[i]];
		}
	}

	private sealed class Output(uint[] inputChainingValue, uint[] blockWords, ulong counter, uint blockLength, uint flags)
	{
		public uint[] ChainingValue()
		{
			return Compress(inputChainingValue, blockWords, counter, blockLength, flags).AsSpan(0, 8).ToArray();
		}

		public void RootOutputBytes(Span<byte> output, ulong position)
		{
			ulong outputBlockCounter = position / BlockLength;
			int offset = (int)(position % BlockLength);

			while (!output.IsEmpty)
			{
				byte[] words = LittleEndianBytes(Compress(inputChainingValue, blockWords, outputBlockCounter, blockLength, flags | Root));
				int length = Math.Min(BlockLength - offset, output.Length);
				words.AsSpan(offset, length).CopyTo(output);
				output = output.Slice(length);
				offset = 0;
				++outputBlockCounter;
			}
		}
	}

	private sealed class ChunkState(uint[] keyWords, ulong chunkCounter, uint flags)
	{
		private readonly byte[] _block = new byte[BlockLength];
		private uint[] _chainingValue = keyWords;
		private int _blockLength;
		private int _blocksCompressed;

		public ulong ChunkCounter => chunkCounter;

		public int Length => BlockLength * _blocksCompressed + _blockLength;

		private uint StartFlag => _blocksCompressed is 0 ? ChunkStart : 0;

		public void Update(ReadOnlySpan<byte> input)
		{
			while (!input.IsEmpty)
			{
				if (_blockLength is BlockLength)
				{
					_chainingValue = Compress(_chainingValue, WordsFromLittleEndianBytes(_block), chunkCounter, BlockLength, flags | StartFlag).AsSpan(0, 8).ToArray();
					++_blocksCompressed;
					_block.AsSpan().Clear();
					_blockLength = 0;
				}

				int take = Math.Min(BlockLength - _blockLength, input.Length);
				input.Slice(0, take).CopyTo(_block.AsSpan(_blockLength));
				_blockLength += take;
				input = input.Slice(take);
			}
		}

		public Output CreateOutput()
		{
			return new Output(_chainingValue, WordsFromLittleEndianBytes(_block), chunkCounter, (uint)_blockLength, flags | StartFlag | ChunkEnd);
		}
	}
}
