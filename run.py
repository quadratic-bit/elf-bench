#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import os
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


LIBRARIES  = ("lief", "elfio", "llvm")
SCENARIOS  = ("parse", "lookup", "write", "remove", "create")
TOPOLOGIES = ("1:N", "N:N")


@dataclass(frozen=True)
class Point:
    scenario: str
    topology: str
    sections: int
    fixture:  Path


@dataclass(frozen=True)
class Invocation:
    summary: dict[str, str]
    samples: list[dict[str, str]]
    output:  str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the in-memory ELF manipulation benchmark matrix."
    )

    parser.add_argument("--lief",          type=Path, default=Path("./bench-lief"))
    parser.add_argument("--elfio",         type=Path, default=Path("./bench-elfio"))
    parser.add_argument("--llvm",          type=Path, default=Path("./bench-llvm"))
    parser.add_argument("--make-fixtures", type=Path, default=Path("./make-fixtures"))

    parser.add_argument("--fixtures-dir",  type=Path, default=Path("fixtures"))
    parser.add_argument("--results-dir",   type=Path, default=Path("results"))
    parser.add_argument("--create-seed",   type=Path, default=Path("write-seed.elf"))

    parser.add_argument("--sections",     default="1,2,4,8,16,32,64,128")
    parser.add_argument("--section-size", default="4K")
    parser.add_argument("--runs",    type=int, default=5)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--chunk",   type=int, default=8)
    parser.add_argument("--cpu",     type=int, required=True)


    parser.add_argument("--target-sample-ms",    type=float, default=100.0)
    parser.add_argument("--calibration-samples", type=int,   default=3)
    parser.add_argument("--max-batch",           type=int,   default=100000)

    args = parser.parse_args()

    if args.runs <= 0:
        parser.error("--runs must be positive")
    if args.samples <= 0:
        parser.error("--samples must be positive")
    if args.warmups < 0:
        parser.error("--warmups cannot be negative")
    if args.chunk <= 0:
        parser.error("--chunk must be positive")
    if args.cpu < 0:
        parser.error("--cpu cannot be negative")
    if args.target_sample_ms <= 0.0:
        parser.error("--target-sample-ms must be positive")
    if args.calibration_samples <= 0:
        parser.error("--calibration-samples must be positive")
    if args.max_batch <= 0:
        parser.error("--max-batch must be positive")

    try:
        args.section_counts = parse_section_counts(args.sections)
    except ValueError as error:
        parser.error(str(error))

    return args


def parse_section_counts(spec: str) -> list[int]:
    values: list[int] = []
    seen:   set [int] = set()

    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue

        try:
            value = int(token, 0)
        except ValueError as error:
            raise ValueError(f"invalid section count: {token}") from error

        if value <= 0:
            raise ValueError("section counts must be positive")
        if value not in seen:
            seen  .add   (value)
            values.append(value)

    if not values:
        raise ValueError("no section counts were specified")

    return values


def pin_cpu(cpu: int) -> None:
    if not hasattr(os, "sched_setaffinity"):
        raise RuntimeError("CPU affinity unavailable")

    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as error:
        raise RuntimeError(f"failed to pin process to CPU {cpu}: {error}") from error


def require_executable(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise RuntimeError(f"executable does not exist: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise RuntimeError(f"file is not executable: {resolved}")
    return resolved


def run_checked(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "command failed with exit code "
            f"{completed.returncode}: {' '.join(command)}\n{completed.stdout}"
        )

    return completed.stdout


def parse_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in line.split(",")[1:]:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


def parse_invocation(output: str) -> Invocation:
    samples: list[dict[str, str]] = []
    summary: dict[str, str] | None = None

    for line in output.splitlines():
        if line.startswith("[i] sample,"):
            samples.append(parse_fields(line))
        elif line.startswith("[i] summary,"):
            summary = parse_fields(line)

    if summary is None:
        raise RuntimeError("no [i] summary line")
    if not samples:
        raise RuntimeError("no [i] sample lines")

    return Invocation(summary=summary, samples=samples, output=output)


def benchmark_command(
    bench: Path,
    point: Point,
    section_size: str,
    warmups: int,
    samples: int,
    batch:   int,
    chunk:   int,
) -> list[str]:
    return [
        str(bench),
        str(point.fixture),
        "--scenario", point.scenario,
        "--topology", point.topology,
        "--sections", str(point.sections),
        "--section-size", section_size,
        "--warmups", str(warmups),
        "--samples", str(samples),
        "--batch",   str(batch),
        "--chunk",   str(chunk),
    ]


def run_benchmark(
    bench: Path,
    point: Point,
    section_size: str,
    warmups: int,
    samples: int,
    batch:   int,
    chunk:   int,
) -> Invocation:
    output = run_checked(
        benchmark_command(bench, point, section_size, warmups, samples, batch, chunk)
    )
    return parse_invocation(output)


def median_ns(invocation: Invocation) -> float:
    return statistics.median(float(sample["ns_per_operation"]) for sample in invocation.samples)


def choose_batch(
    bench: Path,
    point: Point,
    args: argparse.Namespace,
    library: str,
    log_directory: Path,
) -> tuple[int, list[dict[str, object]]]:
    target_ns = args.target_sample_ms * 1_000_000.0
    rows: list[dict[str, object]] = []

    first = run_benchmark(
        bench,
        point,
        args.section_size,
        min(args.warmups, 2),
        args.calibration_samples,
        1,
        args.chunk,
    )
    first_median = median_ns(first)
    if first_median <= 0.0:
        raise RuntimeError("calibration produced a non-positive median")

    estimated = max(1, min(args.max_batch, round(target_ns / first_median)))

    first_log = log_directory / calibration_log_name(library, point, 1)
    first_log.write_text(first.output, encoding="utf-8")
    rows.append({
        "library":  library,
        "scenario": point.scenario,
        "topology": point.topology,
        "sections": point.sections,
        "phase": 1,
        "batch": 1,
        "median_ns_per_operation": f"{first_median:.6f}",
        "median_sample_ms": f"{first_median / 1_000_000.0:.6f}",
        "log": str(first_log),
    })

    second = run_benchmark(
        bench,
        point,
        args.section_size,
        min(args.warmups, 2),
        args.calibration_samples,
        estimated,
        args.chunk,
    )
    second_median = median_ns(second)
    observed_sample_ns = second_median * estimated
    if observed_sample_ns <= 0.0:
        raise RuntimeError("calibration produced a non-positive sample duration")

    final_batch = round(estimated * target_ns / observed_sample_ns)
    final_batch = max(1, min(args.max_batch, final_batch))

    second_log = log_directory / calibration_log_name(library, point, 2)
    second_log.write_text(second.output, encoding="utf-8")
    rows.append({
        "library": library,
        "scenario": point.scenario,
        "topology": point.topology,
        "sections": point.sections,
        "phase": 2,
        "batch": estimated,
        "median_ns_per_operation": f"{second_median:.6f}",
        "median_sample_ms": f"{observed_sample_ns / 1_000_000.0:.6f}",
        "log": str(second_log),
    })

    return final_batch, rows


def topology_slug(topology: str) -> str:
    return "1n" if topology == "1:N" else "nn"


def calibration_log_name(library: str, point: Point, phase: int) -> str:
    return (
        f"calibrate-{library}-{point.scenario}-{topology_slug(point.topology)}-"
        f"n{point.sections}-p{phase}.log"
    )


def measurement_log_name(library: str, point: Point, run: int) -> str:
    return (
        f"measure-{library}-{point.scenario}-{topology_slug(point.topology)}-"
        f"n{point.sections}-r{run}.log"
    )


def create_fixtures(
    generator: Path,
    fixture_directory: Path,
    section_counts: list[int],
    section_size: str,
) -> dict[tuple[str, int], Path]:
    fixture_directory.mkdir(parents=True, exist_ok=True)
    fixtures: dict[tuple[str, int], Path] = {}

    for topology in TOPOLOGIES:
        for sections in section_counts:
            path = fixture_directory / (
                f"{topology_slug(topology)}-n{sections}.elf"
            )

            run_checked([
                str(generator),
                str(path),
                "--topology", topology,
                "--sections", str(sections),
                "--section-size", section_size,
            ])
            fixtures[(topology, sections)] = path.resolve()

    return fixtures


def make_points(
    fixtures: dict[tuple[str, int], Path],
    section_counts: list[int],
    create_seed: Path,
) -> list[Point]:
    return [
        Point(
            scenario=scenario,
            topology=topology,
            sections=sections,
            fixture=(
                create_seed
                if scenario == "create"
                else fixtures[(topology, sections)]
            ),
        )
        for scenario in SCENARIOS
        for topology in TOPOLOGIES
        for sections in section_counts
    ]


def write_header(file, fieldnames: list[str]) -> csv.DictWriter:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    file.flush()
    return writer


def write_point_aggregates(
    path: Path,
    run_rows: list[dict[str, object]],
) -> None:
    groups: dict[tuple[str, str, str, int], list[dict[str, object]]] = {}

    for row in run_rows:
        key = (
            str(row["library"]),
            str(row["scenario"]),
            str(row["topology"]),
            int(row["sections"]),
        )
        groups.setdefault(key, []).append(row)

    fieldnames = [
        "library",
        "scenario",
        "topology",
        "sections",
        "runs",
        "median_of_run_medians_ns",
        "min_run_median_ns",
        "max_run_median_ns",
        "run_spread_percent",
        "max_abs_drift_percent",
        "total_outliers",
    ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for key in sorted(groups):
            rows      = groups[key]
            medians   = [float(row["median_ns"]) for row in rows]
            center    = statistics.median(medians)
            minimum   = min(medians)
            maximum   = max(medians)
            spread    = 100.0 * (maximum - minimum) / center if center else float("inf")
            max_drift = max(abs(float(row["drift_percent"])) for row in rows)
            outliers  = sum(int(row["outliers"]) for row in rows)

            writer.writerow({
                "library":  key[0],
                "scenario": key[1],
                "topology": key[2],
                "sections": key[3],
                "runs": len(rows),
                "median_of_run_medians_ns": f"{center   :.6f}",
                "min_run_median_ns":        f"{minimum  :.6f}",
                "max_run_median_ns":        f"{maximum  :.6f}",
                "run_spread_percent":       f"{spread   :.6f}",
                "max_abs_drift_percent":    f"{max_drift:.6f}",
                "total_outliers": outliers,
            })


def library_order(seed: int) -> tuple[str, ...]:
    order = list(LIBRARIES)

    shift = seed % len(order)
    order = order[shift:] + order[:shift]

    if (seed // len(order)) & 1:
        order.reverse()

    return tuple(order)


def supported(library: str, point: Point) -> bool:
    if (library == "lief" and point.scenario == "create" and point.topology == "1:N"):
        return False

    if (library == "llvm" and point.scenario not in ("parse", "lookup")):
        return False

    if (library == "elfio" and point.scenario == "remove"):
        return False

    return True


def main() -> int:
    args = parse_args()

    try:
        pin_cpu(args.cpu)

        benches = {
            "lief":   require_executable(args.lief),
            "elfio":  require_executable(args.elfio),
            "llvm":   require_executable(args.llvm),
        }
        generator = require_executable(args.make_fixtures)

        args.results_dir.mkdir(parents=True, exist_ok=True)
        log_directory = args.results_dir / "logs"
        log_directory.mkdir(parents=True, exist_ok=True)

        fixtures = create_fixtures(
            generator,
            args.fixtures_dir,
            args.section_counts,
            args.section_size,
        )

        create_seed = args.create_seed.resolve()

        if not create_seed.is_file():
            raise RuntimeError(f"create seed does not exist: {create_seed}")

        points = make_points(fixtures, args.section_counts, create_seed)

        calibration_path = args.results_dir / "calibration.csv"
        runs_path        = args.results_dir / "runs.csv"
        samples_path     = args.results_dir / "samples.csv"
        points_path      = args.results_dir / "points.csv"

        calibration_fields = [
            "library",
            "scenario",
            "topology",
            "sections",
            "phase",
            "batch",
            "median_ns_per_operation",
            "median_sample_ms",
            "log",
        ]
        run_fields = [
            "library",
            "scenario",
            "topology",
            "sections",
            "run",
            "batch",
            "mean_ns",
            "median_ns",
            "sigma_ns",
            "mad_ns",
            "min_ns",
            "max_ns",
            "outliers",
            "drift_percent",
            "log",
        ]
        sample_fields = [
            "library",
            "scenario",
            "topology",
            "sections",
            "run",
            "batch",
            "sample",
            "elapsed_ns",
            "ns_per_operation",
            "output_bytes",
        ]

        batches:  dict[tuple[str, str, str, int], int] = {}
        run_rows: list[dict[str, object]] = []

        with (
            calibration_path.open("w", newline="", encoding="utf-8") as calibration_file,
            runs_path       .open("w", newline="", encoding="utf-8") as runs_file,
            samples_path    .open("w", newline="", encoding="utf-8") as samples_file,
        ):
            calibration_writer = write_header(calibration_file, calibration_fields)
            runs_writer        = write_header(runs_file, run_fields)
            samples_writer     = write_header(samples_file, sample_fields)

            print("calibrating batch sizes", flush=True)
            for point_index, point in enumerate(points):
                order = tuple(
                    library
                    for library in library_order(point_index)
                    if supported(library, point)
                )
                for library in order:
                    batch, calibration_rows = choose_batch(
                        benches[library],
                        point,
                        args,
                        library,
                        log_directory,
                    )
                    batches[(library, point.scenario, point.topology, point.sections)] = batch
                    for row in calibration_rows:
                        calibration_writer.writerow(row)
                    calibration_file.flush()

                    print(
                        f"  {library:5s} {point.scenario:5s} {point.topology:3s} "
                        f"N={point.sections:<4d} batch={batch}",
                        flush=True,
                    )

            for run_index in range(args.runs):
                print(f"measurement sweep {run_index + 1}/{args.runs}", flush=True)
                ordered_points = points if run_index % 2 == 0 else list(reversed(points))

                for point_index, point in enumerate(ordered_points):
                    order = tuple(
                        library
                        for library in library_order(
                            run_index * len(points) + point_index
                        )
                        if supported(library, point)
                    )
                    for library in order:
                        batch = batches[(
                            library,
                            point.scenario,
                            point.topology,
                            point.sections,
                        )]

                        invocation = run_benchmark(
                            benches[library],
                            point,
                            args.section_size,
                            args.warmups,
                            args.samples,
                            batch,
                            args.chunk,
                        )

                        log_path = log_directory / measurement_log_name(
                            library,
                            point,
                            run_index + 1,
                        )
                        log_path.write_text(invocation.output, encoding="utf-8")

                        summary = invocation.summary
                        run_row: dict[str, object] = {
                            "library":   library,
                            "scenario":  point.scenario,
                            "topology":  point.topology,
                            "sections":  point.sections,
                            "run":       run_index + 1,
                            "batch":     batch,
                            "mean_ns":   summary["mean_ns"],
                            "median_ns": summary["median_ns"],
                            "sigma_ns":  summary["sigma_ns"],
                            "mad_ns":    summary["mad_ns"],
                            "min_ns":    summary["min_ns"],
                            "max_ns":    summary["max_ns"],
                            "outliers":  summary["outliers"],
                            "drift_percent": summary["drift_percent"],
                            "log": str(log_path),
                        }
                        runs_writer.writerow(run_row)
                        runs_file.flush()
                        run_rows.append(run_row)

                        for sample_index, sample in enumerate(invocation.samples):
                            samples_writer.writerow({
                                "library":    library,
                                "scenario":   point.scenario,
                                "topology":   point.topology,
                                "sections":   point.sections,
                                "run":        run_index + 1,
                                "batch":      batch,
                                "sample":     sample.get("index", sample_index),
                                "elapsed_ns": sample["elapsed_ns"],
                                "ns_per_operation": sample["ns_per_operation"],
                                "output_bytes": sample["output_bytes"],
                            })
                        samples_file.flush()

                        print(
                            f"  {library:7s} {point.scenario:6s} {point.topology:3s} "
                            f"N={point.sections:<4d} median={float(summary['median_ns']):.3f}ns "
                            f"drift={float(summary['drift_percent']):+.2f}% "
                            f"outliers={summary['outliers']}",
                            flush=True,
                        )

        write_point_aggregates(points_path, run_rows)

        print(f"samples:     {samples_path}")
        print(f"runs:        {runs_path}")
        print(f"points:      {points_path}")
        print(f"calibration: {calibration_path}")
        print(f"logs:        {log_directory}")
        return 0

    except (KeyError, OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
