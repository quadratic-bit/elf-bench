#pragma once

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <time.h>
#include <vector>

namespace elfbench {

constexpr std::uint64_t DEFAULT_SEED      = 0x6767676767676767ULL;
constexpr double        OUTLIER_THRESHOLD = 3.5;
constexpr std::uint64_t CREATE_LOAD_BASE  = 0x100000000ULL;
constexpr std::uint64_t CREATE_ALIGNMENT  = 0x1000ULL;

[[noreturn]] inline void fail(const std::string &message) {
	throw std::runtime_error(message);
}

enum class Scenario { Parse, Lookup, Write, Remove, Create };

enum class Topology { OneToN, NToN };

struct Config {
	std::string input_path;
	Scenario scenario = Scenario::Parse;
	Topology topology = Topology::OneToN;

	std::uint64_t sections     = 0;
	std::uint64_t section_size = 4096;

	std::uint64_t seed = DEFAULT_SEED;

	std::uint64_t warmups = 5;
	std::uint64_t samples = 30;
	std::uint64_t batch   = 1;
	std::uint64_t chunk   = 1;
};

struct Sample {
	std::uint64_t elapsed_ns       = 0;
	double        ns_per_operation = 0.0;
	std::uint64_t output_bytes     = 0;
};

struct Statistics {
	double      mean     = 0.0;
	double      median   = 0.0;
	double      sigma    = 0.0;
	double      mad      = 0.0;
	double      minimum  = 0.0;
	double      maximum  = 0.0;
	std::size_t outliers = 0;
	double      drift    = 0.0;
};

inline volatile std::uint64_t observable_sink = 0;

inline std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
	if (alignment == 0) fail("zero alignment");

	const std::uint64_t remainder = value % alignment;
	if (remainder == 0) return value;

	const std::uint64_t increment = alignment - remainder;
	if (value > std::numeric_limits<std::uint64_t>::max() - increment)
		fail("alignment overflow");

	return value + increment;
}

inline const char *scenario_name(Scenario scenario) {
	switch (scenario) {
	case Scenario::Parse:  return "parse";
	case Scenario::Lookup: return "lookup";
	case Scenario::Write:  return "write";
	case Scenario::Remove: return "remove";
	case Scenario::Create: return "create";
	}

	fail("unknown scenario");
}

inline const char *topology_name(Topology topology) {
	switch (topology) {
		case Topology::OneToN: return "1:N";
		case Topology::NToN:   return "N:N";
	}
	return "unknown";
}

inline std::uint64_t parse_number(const char *text, bool scaled) {
	if (text == nullptr || *text == '\0' || *text == '-')
		fail("invalid numeric argument");

	errno = 0;
	char *end = nullptr;
	const unsigned long long value = std::strtoull(text, &end, 0);
	if (errno != 0 || end == text)
		fail("invalid numeric argument: " + std::string(text));

	std::uint64_t multiplier = 1;
	if (scaled && *end != '\0') {
		switch (*end++) {
			case 'K': case 'k': multiplier = std::uint64_t{1} << 10; break;
			case 'M': case 'm': multiplier = std::uint64_t{1} << 20; break;
			case 'G': case 'g': multiplier = std::uint64_t{1} << 30; break;
			case 'T': case 't': multiplier = std::uint64_t{1} << 40; break;
			default: fail("invalid size suffix: " + std::string(text));
		}

		if ((*end == 'i' || *end == 'I') && (end[1] == 'b' || end[1] == 'B')) {
			end += 2;
		} else if (*end == 'b' || *end == 'B') {
			++end;
		}
	}

	if (*end != '\0')
		fail("invalid numeric argument: " + std::string(text));

	if (value > std::numeric_limits<std::uint64_t>::max() / multiplier)
		fail("numeric argument overflows uint64_t: " + std::string(text));

	return static_cast<std::uint64_t>(value) * multiplier;
}

inline void usage(std::ostream &out, const char *program) {
	out
		<< "Usage:\n"
		<< "  " << program << " <input-elf> --scenario parse|lookup|write|remove|create"
		<< " --topology 1:N|N:N --sections N [options]\n\n"
		<< "Options:\n"
		<< "  --section-size N   Size of one .bench.* section (default: 4K)\n"
		<< "  --seed N\n"
		<< "  --warmups N        (default: 5)\n"
		<< "  --samples N        (default: 30)\n"
		<< "  --batch N          Operations averaged into one sample (default: 1)\n"
		<< "  --chunk N          Maximum live parsed/output objects per timed chunk"
		<< "  -h, --help\n";
}

inline Config parse_args(int argc, char **argv) {
	if (argc == 2 && (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0)) {
		usage(std::cout, argv[0]);
		std::exit(0);
	}

	if (argc < 2) {
		usage(std::cerr, argv[0]);
		fail("missing input ELF");
	}

	Config cfg;
	cfg.input_path = argv[1];

	bool have_scenario = false;
	bool have_topology = false;
	bool have_sections = false;

	for (int i = 2; i < argc; ++i) {
		const std::string_view option = argv[i];
		if (option == "-h" || option == "--help") {
			usage(std::cout, argv[0]);
			std::exit(0);
		}

		if (i + 1 >= argc)
			fail("missing value for option: " + std::string(option));

		const char *value = argv[++i];

		if (option == "--scenario") {
			if (std::strcmp(value, "parse") == 0) {
				cfg.scenario = Scenario::Parse;
			} else if (std::strcmp(value, "lookup") == 0) {
				cfg.scenario = Scenario::Lookup;
			} else if (std::strcmp(value, "write") == 0) {
				cfg.scenario = Scenario::Write;
			} else if (std::strcmp(value, "remove") == 0) {
				cfg.scenario = Scenario::Remove;
			} else if (std::strcmp(value, "create") == 0) {
				cfg.scenario = Scenario::Create;
			} else {
				fail("--scenario must be parse, lookup, write, remove or create");
			}
			have_scenario = true;
		} else if (option == "--topology") {
			if (std::strcmp(value, "1:N") == 0 || std::strcmp(value, "1:n") == 0) {
				cfg.topology = Topology::OneToN;
			} else if (std::strcmp(value, "N:N") == 0 || std::strcmp(value, "n:n") == 0) {
				cfg.topology = Topology::NToN;
			} else {
				fail("--topology must be 1:N or N:N");
			}
			have_topology = true;
		} else if (option == "--sections") {
			cfg.sections = parse_number(value, false);
			have_sections = true;
		} else if (option == "--section-size") {
			cfg.section_size = parse_number(value, true);
		} else if (option == "--seed") {
			cfg.seed = parse_number(value, false);
		} else if (option == "--warmups") {
			cfg.warmups = parse_number(value, false);
		} else if (option == "--samples") {
			cfg.samples = parse_number(value, false);
		} else if (option == "--batch") {
			cfg.batch = parse_number(value, false);
		} else if (option == "--chunk") {
			cfg.chunk = parse_number(value, false);
		} else {
			fail("unknown option: " + std::string(option));
		}
	}

	if (!have_scenario) fail("missing --scenario");
	if (!have_topology) fail("missing --topology");
	if (!have_sections) fail("missing --sections");

	if (cfg.sections == 0 || cfg.section_size == 0 || cfg.samples == 0 ||
	    cfg.batch    == 0 || cfg.chunk        == 0)
	{
		fail("sections, section-size, samples, batch and chunk must be nonzero");
	}

	if (cfg.sections     > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())||
	    cfg.section_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
	{
		fail("requested workload does not fit size_t");
	}

	return cfg;
}

inline std::vector<std::uint8_t> read_file(const std::string &path) {
	std::ifstream input(path, std::ios::binary | std::ios::ate);
	if (!input) fail("failed to open input ELF: " + path);

	const std::streamoff end = input.tellg();
	if (end <= 0)
		fail("input ELF is empty or unreadable: " + path);
	if (static_cast<std::uint64_t>(end) >
	    static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
	{
		fail("input ELF is too large for this process");
	}

	std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
	input.seekg(0, std::ios::beg);
	input.read(reinterpret_cast<char *>(bytes.data()), end);

	if (!input) fail("failed to read input ELF: " + path);

	return bytes;
}

inline std::uint64_t monotonic_raw_ns() {
	timespec now{};
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0) {
		fail("clock_gettime(CLOCK_MONOTONIC_RAW) failed");
	}

	return static_cast<std::uint64_t>(now.tv_sec) * 1'000'000'000ULL +
	       static_cast<std::uint64_t>(now.tv_nsec);
}

inline std::uint64_t mix64(std::uint64_t value) {
	value ^= value >> 30;
	value *= 0xbf58476d1ce4e5b9ULL;
	value ^= value >> 27;
	value *= 0x94d049bb133111ebULL;
	value ^= value >> 31;
	return value;
}

inline std::vector<std::vector<std::uint8_t>> make_payloads(const Config &cfg) {
	std::vector<std::vector<std::uint8_t>> payloads;
	payloads.reserve(static_cast<std::size_t>(cfg.sections));

	for (std::uint64_t section = 0; section < cfg.sections; ++section) {
		std::vector<std::uint8_t> payload(static_cast<std::size_t>(cfg.section_size));
		std::uint64_t state = mix64(cfg.seed ^ mix64(section + 0x9e3779b97f4a7c15ULL));

		for (std::size_t offset = 0; offset < payload.size();) {
			state = mix64(state + offset + 0xd1b54a32d192ed03ULL);
			for (unsigned byte = 0; byte < 8 && offset < payload.size(); ++byte, ++offset) {
				payload[offset] = static_cast<std::uint8_t>(state >> (byte * 8));
			}
		}

		payloads.push_back(std::move(payload));
	}

	return payloads;
}

inline double median(std::vector<double> values) {
	if (values.empty()) fail("cannot compute median of empty data");
	std::sort(values.begin(), values.end());
	const std::size_t middle = values.size() / 2;

	if ((values.size() & 1U) != 0) return values[middle];

	return (values[middle - 1] + values[middle]) / 2.0;
}

inline Statistics calculate_statistics(const std::vector<Sample> &samples) {
	if (samples.empty()) fail("cannot calculate statistics for empty samples");

	std::vector<double> values;
	values.reserve(samples.size());
	for (const Sample &sample : samples)
		values.push_back(sample.ns_per_operation);

	Statistics stats;
	stats.minimum = *std::min_element(values.begin(), values.end());
	stats.maximum = *std::max_element(values.begin(), values.end());
	stats.mean    =  std::accumulate (values.begin(), values.end(), 0.0) /
	                                 static_cast<double>(values.size());
	stats.median  =  median(values);

	if (values.size() > 1) {
		double sum = 0.0;
		for (double val : values) {
			const double d = val - stats.mean;
			sum += d * d;
		}
		stats.sigma = std::sqrt(sum / static_cast<double>(values.size() - 1));
	}

	std::vector<double> deviations;
	deviations.reserve(values.size());

	for (double val : values) deviations.push_back(std::abs(val - stats.median));
	stats.mad = median(deviations);

	if (stats.mad > 0.0) {
		constexpr double MAD_NORM = 0.6744897501960817;
		for (double val : values) {
			const double modified_z = MAD_NORM * (val - stats.median) / stats.mad;
			if (std::abs(modified_z) > OUTLIER_THRESHOLD) ++stats.outliers;
		}
	}

	if (values.size() >= 4 && stats.median != 0.0) {
		const std::size_t middle = values.size() / 2;
		std::vector<double> first (values.begin(), values.begin() + middle);
		std::vector<double> second(values.begin() + middle, values.end());
		stats.drift = (median(second) - median(first)) / stats.median;
	}

	return stats;
}

inline void consume_bytes(const std::vector<std::uint8_t> &bytes) {
	std::uint64_t value = static_cast<std::uint64_t>(bytes.size());
	if (!bytes.empty()) {
		value ^= static_cast<std::uint64_t>(bytes.front())           << 8;
		value ^= static_cast<std::uint64_t>(bytes[bytes.size() / 2]) << 16;
		value ^= static_cast<std::uint64_t>(bytes.back())            << 24;
	}
	observable_sink = observable_sink ^ mix64(value);
}

template<class Adapter>
Sample run_parse_sample(const Config &cfg, const std::vector<std::uint8_t> &input) {
	std::uint64_t elapsed   = 0;
	std::uint64_t remaining = cfg.batch;

	while (remaining != 0) {
		const std::uint64_t chunk_size = std::min(remaining, cfg.chunk);
		std::vector<typename Adapter::BinaryPtr> binaries;
		binaries.reserve(static_cast<std::size_t>(chunk_size));

		const std::uint64_t begin = monotonic_raw_ns();
		for (std::uint64_t i = 0; i < chunk_size; ++i)
			binaries.push_back(Adapter::parse(input));
		const std::uint64_t end = monotonic_raw_ns();
		elapsed += end - begin;

		for (const auto &binary : binaries)
			observable_sink = observable_sink ^ Adapter::consume(*binary);

		remaining -= chunk_size;
	}

	Sample sample;
	sample.elapsed_ns = elapsed;
	sample.ns_per_operation = static_cast<double>(elapsed) / static_cast<double>(cfg.batch);
	return sample;
}

template<class Adapter>
Sample run_lookup_sample(const Config &cfg, const std::vector<std::uint8_t> &input) {
	std::uint64_t elapsed   = 0;
	std::uint64_t remaining = cfg.batch;
	std::uint64_t checksum  = 0;

	while (remaining != 0) {
		const std::uint64_t chunk_size = std::min(remaining, cfg.chunk);

		std::vector<typename Adapter::BinaryPtr> binaries;
		binaries.reserve(static_cast<std::size_t>(chunk_size));

		for (std::uint64_t i = 0; i < chunk_size; ++i)
			binaries.push_back(Adapter::parse(input));

		const std::uint64_t begin = monotonic_raw_ns();

		for (auto &binary : binaries)
			checksum ^= Adapter::lookup_sections(*binary, cfg);

		const std::uint64_t end = monotonic_raw_ns();
		elapsed += end - begin;

		for (const auto &binary : binaries)
			observable_sink = observable_sink ^ Adapter::consume(*binary);

		remaining -= chunk_size;
	}

	observable_sink = observable_sink ^ mix64(checksum);

	Sample sample;
	sample.elapsed_ns = elapsed;
	sample.ns_per_operation = static_cast<double>(elapsed) / static_cast<double>(cfg.batch);

	return sample;
}

template<class Adapter>
Sample run_write_sample(
	const Config &cfg,
	const std::vector<std::uint8_t> &input,
	const std::vector<std::vector<std::uint8_t>> &payloads
) {
	std::uint64_t elapsed      = 0;
	std::uint64_t remaining    = cfg.batch;
	std::uint64_t output_bytes = 0;

	while (remaining != 0) {
		const std::uint64_t chunk_size = std::min(remaining, cfg.chunk);

		std::vector<typename Adapter::BinaryPtr> binaries;
		binaries.reserve(static_cast<std::size_t>(chunk_size));
		for (std::uint64_t i = 0; i < chunk_size; ++i)
			binaries.push_back(Adapter::prepare_mutable(input));

		std::vector<std::vector<std::uint8_t>> outputs;
		outputs.reserve(static_cast<std::size_t>(chunk_size));

		const std::uint64_t begin = monotonic_raw_ns();
		for (auto &binary : binaries) {
			Adapter::replace_payloads(*binary, cfg, payloads);
			outputs.push_back(Adapter::serialize(*binary));
		}
		const std::uint64_t end = monotonic_raw_ns();
		elapsed += end - begin;

		for (const auto &output : outputs) {
			if (output.empty())
				fail("serializer returned an empty ELF");
			if (output_bytes == 0) {
				output_bytes = static_cast<std::uint64_t>(output.size());
			} else if (output_bytes != static_cast<std::uint64_t>(output.size())) {
				fail("serialized size changed between identical operations");
			}
			consume_bytes(output);
		}

		remaining -= chunk_size;
	}

	Sample sample;
	sample.elapsed_ns       = elapsed;
	sample.ns_per_operation = static_cast<double>(elapsed) / static_cast<double>(cfg.batch);
	sample.output_bytes     = output_bytes;
	return sample;
}

template<class Adapter>
Sample run_remove_sample(const Config &cfg, const std::vector<std::uint8_t> &input) {
	std::uint64_t elapsed      = 0;
	std::uint64_t remaining    = cfg.batch;
	std::uint64_t output_bytes = 0;

	while (remaining != 0) {
		const std::uint64_t chunk_size = std::min(remaining, cfg.chunk);

		std::vector<typename Adapter::BinaryPtr> binaries;
		binaries.reserve(static_cast<std::size_t>(chunk_size));

		for (std::uint64_t i = 0; i < chunk_size; ++i)
			binaries.push_back(Adapter::prepare_mutable(input));

		std::vector<std::vector<std::uint8_t>> outputs;
		outputs.reserve(static_cast<std::size_t>(chunk_size));

		const std::uint64_t begin = monotonic_raw_ns();

		for (auto &binary : binaries) {
			Adapter::remove_sections(*binary, cfg);
			outputs.push_back(Adapter::serialize(*binary));
		}

		const std::uint64_t end = monotonic_raw_ns();
		elapsed += end - begin;

		for (const auto &output : outputs) {
			if (output.empty()) fail("serializer returned an empty ELF");

			const std::uint64_t size = static_cast<std::uint64_t>(output.size());

			if (output_bytes == 0) {
				output_bytes = size;
			} else if (output_bytes != size) {
				fail("serialized size changed between identical operations");
			}

			consume_bytes(output);
		}

		remaining -= chunk_size;
	}

	Sample sample;
	sample.elapsed_ns       = elapsed;
	sample.ns_per_operation = static_cast<double>(elapsed) / static_cast<double>(cfg.batch);
	sample.output_bytes     = output_bytes;

	return sample;
}

template<class Adapter>
Sample run_create_sample(
	const Config &cfg,
	const std::vector<std::uint8_t> &input,
	const std::vector<std::vector<std::uint8_t>> &payloads
) {
	std::uint64_t elapsed      = 0;
	std::uint64_t remaining    = cfg.batch;
	std::uint64_t output_bytes = 0;

	while (remaining != 0) {
		const std::uint64_t chunk_size = std::min(remaining, cfg.chunk);

		std::vector<typename Adapter::BinaryPtr> binaries;
		binaries.reserve(static_cast<std::size_t>(chunk_size));

		for (std::uint64_t i = 0; i < chunk_size; ++i)
			binaries.push_back(Adapter::prepare_mutable(input));

		std::vector<std::vector<std::uint8_t>> outputs;
		outputs.reserve(static_cast<std::size_t>(chunk_size));

		const std::uint64_t begin = monotonic_raw_ns();

		for (auto &binary : binaries) {
			Adapter::create_workload(*binary, cfg, payloads);
			outputs.push_back(Adapter::serialize(*binary));
		}

		const std::uint64_t end = monotonic_raw_ns();
		elapsed += end - begin;

		for (const auto &output : outputs) {
			if (output.empty()) fail("serializer returned an empty ELF");

			const std::uint64_t size = static_cast<std::uint64_t>(output.size());

			if (output_bytes == 0) {
				output_bytes = size;
			} else if (output_bytes != size) {
				fail("serialized size changed between identical operations");
			}

			consume_bytes(output);
		}

		remaining -= chunk_size;
	}

	Sample sample;
	sample.elapsed_ns       = elapsed;
	sample.ns_per_operation = static_cast<double>(elapsed) / static_cast<double>(cfg.batch);
	sample.output_bytes     = output_bytes;
	return sample;
}

template<class Adapter>
void preflight(
	const Config &cfg,
	const std::vector<std::uint8_t> &input,
	const std::vector<std::vector<std::uint8_t>> &payloads
) {
	const bool mutable_scenario =
		cfg.scenario == Scenario::Write  ||
		cfg.scenario == Scenario::Remove ||
		cfg.scenario == Scenario::Create;

	auto binary = mutable_scenario
		? Adapter::prepare_mutable(input)
		: Adapter::parse(input);

	if (cfg.scenario != Scenario::Create)
		Adapter::validate_fixture(*binary, cfg);

	if (cfg.scenario == Scenario::Lookup) {
		observable_sink = observable_sink ^ Adapter::lookup_sections(*binary, cfg);
	} else if (cfg.scenario == Scenario::Write) {
		Adapter::replace_payloads(*binary, cfg, payloads);

		std::vector<std::uint8_t> output = Adapter::serialize(*binary);

		if (output.empty())
			fail("preflight serializer returned an empty ELF");

		auto reparsed = Adapter::parse(output);
		Adapter::validate_fixture (*reparsed, cfg);
		Adapter::validate_payloads(*reparsed, cfg, payloads);
		consume_bytes(output);
	} else if (cfg.scenario == Scenario::Remove) {
		Adapter::remove_sections(*binary, cfg);

		std::vector<std::uint8_t> output = Adapter::serialize(*binary);

		if (output.empty())
			fail("preflight serializer returned an empty ELF");

		auto reparsed = Adapter::parse(output);
		Adapter::validate_removed(*reparsed, cfg);
		consume_bytes(output);
	} else if (cfg.scenario == Scenario::Create) {
		Adapter::create_workload(*binary, cfg, payloads);

		std::vector<std::uint8_t> output = Adapter::serialize(*binary);

		if (output.empty())
			fail("preflight serializer returned an empty ELF");

		auto reparsed = Adapter::parse(output);
		Adapter::validate_fixture (*reparsed, cfg);
		Adapter::validate_payloads(*reparsed, cfg, payloads);
		consume_bytes(output);
	}
}

template<class Adapter>
int benchmark_main(int argc, char **argv) {
try {
	const Config cfg = parse_args(argc, argv);

	const std::vector<std::uint8_t> input = read_file(cfg.input_path);

	std::vector<std::vector<std::uint8_t>> payloads;

	if (cfg.scenario == Scenario::Write || cfg.scenario == Scenario::Create) {
		payloads = make_payloads(cfg);
	}

	preflight<Adapter>(cfg, input, payloads);

	timespec resolution{};
	if (clock_getres(CLOCK_MONOTONIC_RAW, &resolution) != 0)
		fail("clock_getres(CLOCK_MONOTONIC_RAW) failed");
	const std::uint64_t resolution_ns =
		static_cast<std::uint64_t>(resolution.tv_sec) * 1'000'000'000ULL +
		static_cast<std::uint64_t>(resolution.tv_nsec);

	std::cout
		<< "[i] config"
		<< ",library="      << Adapter::name()
		<< ",scenario="     << scenario_name(cfg.scenario)
		<< ",topology="     << topology_name(cfg.topology)
		<< ",sections="     << cfg.sections
		<< ",section_size=" << cfg.section_size
		<< ",input_bytes="  << input.size()
		<< ",warmups="      << cfg.warmups
		<< ",samples="      << cfg.samples
		<< ",batch="        << cfg.batch
		<< ",chunk="        << cfg.chunk
		<< ",seed="         << cfg.seed
		<< ",clock=CLOCK_MONOTONIC_RAW"
		<< ",clock_resolution_ns=" << resolution_ns
		<< '\n';

	auto run_one = [&]() {
		switch (cfg.scenario) {
		case Scenario::Parse:  return run_parse_sample <Adapter>(cfg, input);
		case Scenario::Lookup: return run_lookup_sample<Adapter>(cfg, input);
		case Scenario::Write:  return run_write_sample <Adapter>(cfg, input, payloads);
		case Scenario::Remove: return run_remove_sample<Adapter>(cfg, input);
		case Scenario::Create: return run_create_sample<Adapter>(cfg, input, payloads);
		}

		fail("unknown scenario");
	};

	for (std::uint64_t i = 0; i < cfg.warmups; ++i)
		(void)run_one();

	std::vector<Sample> samples;
	samples.reserve(static_cast<std::size_t>(cfg.samples));
	for (std::uint64_t i = 0; i < cfg.samples; ++i) {
		Sample sample = run_one();
		samples.push_back(sample);
		std::cout
			<< std::fixed << std::setprecision(3)
			<< "[i] sample"
			<< ",index="            << i
			<< ",elapsed_ns="       << sample.elapsed_ns
			<< ",ns_per_operation=" << sample.ns_per_operation
			<< ",output_bytes="     << sample.output_bytes
			<< '\n';
	}

	const Statistics stats = calculate_statistics(samples);
	std::cout
		<< std::fixed << std::setprecision(3)
		<< "[i] summary"
		<< ",library="       << Adapter::name()
		<< ",scenario="      << scenario_name(cfg.scenario)
		<< ",topology="      << topology_name(cfg.topology)
		<< ",sections="      << cfg.sections
		<< ",samples="       << samples.size()
		<< ",mean_ns="       << stats.mean
		<< ",median_ns="     << stats.median
		<< ",sigma_ns="      << stats.sigma
		<< ",mad_ns="        << stats.mad
		<< ",min_ns="        << stats.minimum
		<< ",max_ns="        << stats.maximum
		<< ",outliers="      << stats.outliers
		<< ",drift_percent=" << stats.drift * 100.0
		<< '\n';

	return 0;
} catch (const std::exception &error) {
	std::cerr << "[e] " << error.what() << '\n';
	return 1;
}
}

} // namespace elfbench
