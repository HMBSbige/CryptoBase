#!/usr/bin/env bash
# Runs the tests from the repository root: optimized Release by default, "tiered" for tiered compilation, "debug" for Debug. "probe" prints the instruction sets that SDE adds, and "shards" checks that each namespace is in exactly one shard.
#   DISABLE   Comma-separated DOTNET_Enable<name> switches to turn off; Vector512 caps vectors at 256 bits instead. Spaces separate test runs, in which "none" turns nothing off.
#   SDE_PATH  Intel SDE kit; the default mode runs under "sde64 -spr" when SDE adds instruction sets this runner lacks.
#   SHARD     Comma-separated shards out of hashes, ciphers, ec and rest: runs only those.
set -eo pipefail

tests=artifacts/bin/CryptoBase.Tests/release/CryptoBase.Tests.dll
sde=("$SDE_PATH/sde64" -spr --)

# Selects the tests in the comma-separated shards. Filters cannot negate, so rest lists every other namespace, the root one first.
shard_filter() {
	local shard name names=() alternatives=()

	for shard in ${1//,/ }; do
		case $shard in
			hashes) names+=(Hashes) ;;
			ciphers) names+=(Ciphers) ;;
			ec) names+=(EllipticCurves KeyAgreements Signatures) ;;
			rest) names+=('' Cavp Encodings IO Kdf Kems Macs Platform Vectors Wycheproof) ;;
			*) echo "Unknown shard: $shard" >&2; return 1 ;;
		esac
	done

	for name in "${names[@]}"; do
		alternatives+=("(CryptoBase.Tests${name:+.$name*})")
	done

	local IFS='|'
	echo "/*/${alternatives[*]}/*/*"
}

# Prints the namespaces of the tests that a filter selects.
namespaces() {
	dotnet "$tests" --list-tests json --treenode-filter "$1" --ignore-exit-code 8 | awk -F'"' '$2 == "namespace" { print $4 }' | sort -u
}

# Sets missing to the instruction sets that SDE adds to this runner's.
probe() {
	local probe=artifacts/bin/InstructionSets/InstructionSets.dll native emulated
	: "${SDE_PATH:?SDE_PATH must name the SDE kit}"
	dotnet build .github/InstructionSets.cs -c Release -o "${probe%/*}" -v q >&2
	native=$(dotnet "$probe")
	emulated=$(DOTNET_EnableDiagnostics=0 "${sde[@]}" dotnet "$probe")
	missing=$(LC_ALL=C comm -13 <(echo "$native") <(echo "$emulated") | paste -sd ' ')
	echo "CPU:$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2); SDE adds: ${missing:-nothing}" >&2
}

# Turns off the comma-separated switches in $1.
turn_off() {
	local switch

	for switch in ${1//,/ }; do
		case $switch in
			none) ;;
			Vector512) export DOTNET_PreferredVectorBitWidth=256 ;;
			*) export "DOTNET_Enable$switch=0" ;;
		esac
	done
}

# Runs the tests once in the mode that $1 names.
run() {
	case $1 in
		'') "${runner[@]}" "$tests" --minimum-expected-tests 1 "${filter[@]}" ;;
		tiered) DOTNET_TieredCompilation=1 dotnet "$tests" --minimum-expected-tests 1 "${filter[@]}" ;;
		debug) dotnet test --project test/CryptoBase.Tests -c Debug -p:RunAnalyzers=false --minimum-expected-tests 1 "${filter[@]}" ;;
	esac
}

case $1 in
	''|tiered|debug) ;;
	probe)
		probe
		echo "$missing"
		exit
		;;
	shards)
		# A namespace missing from rest would go untested. The wildcard filter, like the shards, leaves out explicit tests.
		all=$(namespaces '/*/*/*/*')
		sharded=$(for shard in hashes ciphers ec rest; do namespaces "$(shard_filter "$shard")"; done | sort)

		if [[ -z $all || $all != "$sharded" ]]; then
			echo 'Each namespace must be in exactly one shard (< missing, > repeated):' >&2
			diff <(echo "$all") <(echo "$sharded") >&2
			exit 1
		fi

		exit
		;;
	*) echo "Unknown mode: $1" >&2; exit 1 ;;
esac

filter=()

if [[ -n $SHARD ]]; then
	shard=$(shard_filter "$SHARD")
	filter=(--treenode-filter "$shard")
fi

runner=(dotnet)

if [[ -z $1 && -n $SDE_PATH ]]; then
	probe

	if [[ -n $missing ]]; then
		runner=("${sde[@]}" dotnet)
		export DOTNET_EnableDiagnostics=0
		# SDE loses emulated vector registers across signal handlers:
		# https://web.archive.org/web/20260113162404/https://community.intel.com/t5/Intel-ISA-Extensions/SDE-signal-handling-bug/td-p/1646699
		# The runtime signals threads to suspend them for GC; make GC wait for them to poll instead.
		export DOTNET_INTERNAL_ThreadSuspendInjection=0
		# Emulated threads allocate too slowly to contend for one heap, so server GC would only add GC threads to emulate.
		export DOTNET_gcServer=0
		# Keep glibc and OpenSSL off emulated AVX-512, which is slow and exposed to the same bug.
		export GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F,-AVX512VL,-AVX512BW,-AVX512DQ,-AVX512CD
		export OPENSSL_ia32cap=:~0x600C0230000
	fi
fi

read -ra runs <<< "$DISABLE"

if (( ${#runs[@]} <= 1 )); then
	turn_off "${runs[0]}"
	run "$1"
	exit
fi

# Runs each in turn and fails at the end if any did.
failed=()

for switches in "${runs[@]}"; do
	echo "::group::DISABLE=$switches"
	( turn_off "$switches"; run "$1" ) || failed+=("$switches")
	echo '::endgroup::'
done

for switches in "${failed[@]}"; do
	echo "::error::The tests failed with DISABLE=$switches."
done

(( ${#failed[@]} == 0 ))
