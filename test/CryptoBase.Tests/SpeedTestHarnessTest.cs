using CryptoBase.SpeedTest.Catalog;
using CryptoBase.SpeedTest.Measuring;
using CryptoBase.SpeedTest.Reporting;
using CryptoBase.SpeedTest.Workloads;
using System.Collections.Immutable;

namespace CryptoBase.Tests;

public class SpeedTestHarnessTest
{
	[Test]
	public async Task OperationColumnsFollowTheGroupOrder()
	{
		ImmutableArray<AlgorithmEntry> selected = AlgorithmSelector.Select(["rsa-2048", "rsa-2048-keygen"], includeSlow: false, out _);
		ImmutableArray<GroupLayout> groups = BenchmarkSession.Plan(selected, [16]);

		await Assert.That(groups.Single().Columns).IsEquivalentTo([OperationNames.KeyGen, OperationNames.Sign, OperationNames.Verify], CollectionOrdering.Matching);
	}

	[Test]
	public async Task OperationColumnsLeaveOutUnusedOperations()
	{
		ImmutableArray<AlgorithmEntry> selected = AlgorithmSelector.Select(["rsa-2048"], includeSlow: false, out _);
		ImmutableArray<GroupLayout> groups = BenchmarkSession.Plan(selected, [16]);

		await Assert.That(groups.Single().Columns).IsEquivalentTo([OperationNames.Sign, OperationNames.Verify], CollectionOrdering.Matching);
	}

	[Test]
	public async Task MultiThreadRunnerRunsEveryWorker()
	{
		CountingWorkload[] workloads = [new(), new(), new()];

		using (MultiThreadBatchRunner runner = new([.. workloads]))
		{
			for (int i = 0; i < 100; ++i)
			{
				runner.RunBatch(7);
			}

			await Assert.That(runner.WorkerCount).IsEqualTo(3);
		}

		foreach (CountingWorkload workload in workloads)
		{
			await Assert.That(workload.Iterations).IsEqualTo(700);
			await Assert.That(workload.IsDisposed).IsTrue();
		}
	}

	[Test]
	public async Task MultiThreadRunnerReportsAWorkerThatThrows()
	{
		using MultiThreadBatchRunner runner = new([new CountingWorkload(), new CountingWorkload { ThrowAfter = 10 }]);

		runner.RunBatch(5);
		await Assert.That(() => runner.RunBatch(10)).ThrowsExactly<InvalidOperationException>().WithMessageContaining("Worker 1");
		await Assert.That(() => runner.RunBatch(1)).ThrowsExactly<InvalidOperationException>();
	}

	[Test]
	public async Task SelfTestPassesTheSelectedWorkloads()
	{
		ImmutableArray<AlgorithmEntry> selected = AlgorithmSelector.Select(["sha256", "aes-128-gcm", "x25519"], includeSlow: false, out _);
		using StringWriter writer = new();

		await Assert.That(SelfTest.Run(selected, [16, 1024], writer)).IsEqualTo(0);
		await Assert.That(writer.ToString()).Contains("Tested 8 workload(s) of 3 algorithm(s)");
	}

	private sealed class CountingWorkload : Workload
	{
		public long Iterations { get; private set; }

		public long ThrowAfter { get; init; } = long.MaxValue;

		public bool IsDisposed { get; private set; }

		public override void Verify()
		{
		}

		public override void Run(long iterations)
		{
			Iterations += iterations;

			if (Iterations > ThrowAfter)
			{
				throw new SelfTestException("The workload failed.");
			}
		}

		public override void Dispose()
		{
			IsDisposed = true;
		}
	}
}
