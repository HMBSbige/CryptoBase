using static CryptoBase.Kdf.Argon2.Argon2Core;

namespace CryptoBase.Kdf.Argon2;

internal readonly unsafe struct Argon2ReferenceSet
{
	private readonly Argon2Block* _memory;
	private readonly Argon2Block* _ownLane;
	private readonly int _lane;
	private readonly uint _lanes;
	private readonly bool _powerOfTwoLanes;
	private readonly uint _laneLength;
	private readonly uint _otherLaneArea;
	private readonly uint _startPosition;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal Argon2ReferenceSet(Argon2Block* memory, int lanes, int segmentLength, int pass, int slice, int lane)
	{
		int laneLength = segmentLength * SyncPoints;

		_memory = memory;
		_ownLane = memory + (nint)lane * laneLength;
		_lane = lane;
		_lanes = (uint)lanes;
		OwnLaneOnly = lanes is 1 || pass is 0 && slice is 0;
		_powerOfTwoLanes = BitOperations.IsPow2(lanes);
		_laneLength = (uint)laneLength;

		_otherLaneArea = pass is 0 ? (uint)(slice * segmentLength) : (uint)(laneLength - segmentLength);
		_startPosition = pass is 0 || slice is SyncPoints - 1 ? 0 : (uint)((slice + 1) * segmentLength);
	}

	internal bool OwnLaneOnly { get; }

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal Argon2Block* Locate(ulong pseudoRandom, int index)
	{
		uint j1 = (uint)pseudoRandom;
		Argon2Block* referenceLane = _ownLane;
		uint areaSize = _otherLaneArea + (uint)index - 1;

		if (!OwnLaneOnly)
		{
			uint j2 = (uint)(pseudoRandom >> 32);
			int lane = _powerOfTwoLanes ? (int)(j2 & _lanes - 1) : (int)(j2 % _lanes);
			referenceLane = _memory + lane * (nint)_laneLength;

			// The JIT keeps selections inside loops as branches, and whether the lane is the own one is pseudo-random and would often mispredict, so a mask selects the area.
			uint otherLaneArea = index is 0 ? _otherLaneArea - 1 : _otherLaneArea;
			uint otherLaneMask = 0u - Unsafe.BitCast<bool, byte>(lane != _lane);
			areaSize ^= (areaSize ^ otherLaneArea) & otherLaneMask;
		}

		return referenceLane + Position(j1, areaSize);
	}

	// Without the code that selects a lane, this keeps fewer values in registers.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal Argon2Block* LocateInOwnLane(ulong pseudoRandom, int index)
	{
		Debug.Assert(OwnLaneOnly);

		return _ownLane + Position((uint)pseudoRandom, _otherLaneArea + (uint)index - 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private uint Position(uint j1, uint areaSize)
	{
		ulong x = (ulong)j1 * j1 >> 32;
		uint position = _startPosition + areaSize - 1 - (uint)(areaSize * x >> 32);

		// Only possible after the first pass; with a single lane, a branch measured faster than a mask.
		if (position >= _laneLength)
		{
			position -= _laneLength;
		}

		return position;
	}
}
