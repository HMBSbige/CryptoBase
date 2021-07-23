using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Digests.CRC32C
{
	public class Crc32CX86 : IHash
	{
		public string Name => @"CRC-32C";

		public int Length => HashConstants.Crc32Length;

		public int BlockSize => HashConstants.Crc32BlockSize;

		private uint _state;

		public static bool IsSupport => Sse42.IsSupported;

		public Crc32CX86()
		{
			Reset();
		}

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Update(origin);
			GetHash(destination);
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			if (Sse42.X64.IsSupported)
			{
				while (source.Length >= 8)
				{
					var data = BinaryPrimitives.ReadUInt64LittleEndian(source);
					_state = (uint)Sse42.X64.Crc32(_state, data);
					source = source[8..];
				}
			}

			while (source.Length >= 4)
			{
				var data = BinaryPrimitives.ReadUInt32LittleEndian(source);
				_state = Sse42.Crc32(_state, data);
				source = source[4..];
			}

			if (source.Length >= 2)
			{
				var data = BinaryPrimitives.ReadUInt16LittleEndian(source);
				_state = Sse42.Crc32(_state, data);
				source = source[2..];
			}

			foreach (var b in source)
			{
				_state = Sse42.Crc32(_state, b);
			}
		}

		public void GetHash(Span<byte> destination)
		{
			BinaryPrimitives.WriteUInt32BigEndian(destination, ~_state);
			Reset();
		}

		public void Reset()
		{
			_state = uint.MaxValue;
		}

		public void Dispose()
		{
			GC.SuppressFinalize(this);
		}
	}
}
