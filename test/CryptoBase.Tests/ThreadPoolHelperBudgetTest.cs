using CryptoBase.Internal;

namespace CryptoBase.Tests;

public class ThreadPoolHelperBudgetTest
{
	public enum QueueFailure
	{
		BeforeQueuing,
		AfterQueuing,
		AfterStarting,
	}

	[Test]
	public async Task ReserveGrantsNoMoreThanTheCapacityLeft()
	{
		ThreadPoolHelperBudget budget = new(4, static _ => { });

		int first = budget.Reserve(3);
		int second = budget.Reserve(3);
		int exhausted = budget.Reserve(1);
		budget.Release(2);
		int afterRelease = budget.Reserve(5);

		using (Assert.Multiple())
		{
			await Assert.That(first).IsEqualTo(3);
			await Assert.That(second).IsEqualTo(1);
			await Assert.That(exhausted).IsEqualTo(0);
			await Assert.That(afterRelease).IsEqualTo(2);
			await Assert.That(budget.Queued).IsEqualTo(4);
		}
	}

	[Test]
	public async Task ConcurrentReservationsNeverExceedTheCapacity()
	{
		const int capacity = 8;
		ThreadPoolHelperBudget budget = new(capacity, static _ => { });
		int exceeded = 0;

		Parallel.For
		(
			0, 100_000, _ =>
			{
				int granted = budget.Reserve(3);

				if (budget.Queued > capacity)
				{
					Interlocked.Exchange(ref exceeded, 1);
				}

				budget.Release(granted);
			}
		);

		using (Assert.Multiple())
		{
			await Assert.That(exceeded).IsEqualTo(0);
			await Assert.That(budget.Queued).IsEqualTo(0);
		}
	}

	[Test]
	public async Task QueueStopsAtTheCapacityUntilHelpersStart()
	{
		List<IThreadPoolWorkItem> queue = [];
		ThreadPoolHelperBudget budget = new(2, queue.Add);
		TestHelper first = new(budget);
		TestHelper second = new(budget);

		int firstQueued = first.Queue(5);
		int secondQueuedWhileFull = second.Queue(1);
		int heldWhileFull = budget.Queued;
		Start(queue, 1);
		int secondQueuedAfterStart = second.Queue(3);
		int heldAfterStart = budget.Queued;
		int waiting = queue.Count;
		Start(queue, waiting);

		using (Assert.Multiple())
		{
			await Assert.That(firstQueued).IsEqualTo(2);
			await Assert.That(secondQueuedWhileFull).IsEqualTo(0);
			await Assert.That(heldWhileFull).IsEqualTo(2);
			await Assert.That(secondQueuedAfterStart).IsEqualTo(1);
			await Assert.That(heldAfterStart).IsEqualTo(2);
			await Assert.That(waiting).IsEqualTo(2);
			await Assert.That(budget.Queued).IsEqualTo(0);
		}
	}

	[Test]
	[Arguments(QueueFailure.BeforeQueuing)]
	[Arguments(QueueFailure.AfterQueuing)]
	[Arguments(QueueFailure.AfterStarting)]
	public async Task FailedQueuingReturnsEveryShareOnce(QueueFailure failure)
	{
		List<IThreadPoolWorkItem> queue = [];
		int attempts = 0;
		ThreadPoolHelperBudget budget = new
		(
			8, helper =>
			{
				if (attempts++ is not 1)
				{
					queue.Add(helper);
					return;
				}

				switch (failure)
				{
					case QueueFailure.AfterQueuing:
					{
						queue.Add(helper);
						break;
					}
					case QueueFailure.AfterStarting:
					{
						helper.Execute();
						break;
					}
				}

				throw new InvalidOperationException();
			}
		);
		TestHelper helper = new(budget);

		await Assert.That(() => { helper.Queue(4); }).ThrowsExactly<InvalidOperationException>();
		int held = budget.Queued;
		int waiting = queue.Count;
		Start(queue, waiting);

		using (Assert.Multiple())
		{
			await Assert.That(held).IsBetween(waiting - 1, waiting);
			await Assert.That(budget.Queued).IsEqualTo(0);
		}
	}

	private static void Start(List<IThreadPoolWorkItem> queue, int count)
	{
		for (int i = 0; i < count; ++i)
		{
			IThreadPoolWorkItem helper = queue[0];
			queue.RemoveAt(0);
			helper.Execute();
		}
	}

	private sealed class TestHelper(ThreadPoolHelperBudget budget) : ThreadPoolHelper(budget)
	{
		public int Queue(int count)
		{
			return QueueHelpers(count);
		}

		internal override void Help()
		{
		}
	}
}
