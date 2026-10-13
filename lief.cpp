#include "common.hpp"

#include <LIEF/ELF.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

using elfbench::Config;
using elfbench::Topology;

struct LIEFAdapter {
	using BinaryPtr = std::unique_ptr<LIEF::ELF::Binary>;

	static const char *name() {
		return "lief";
	}

	static BinaryPtr parse(const std::vector<std::uint8_t> &input) {
		BinaryPtr binary = LIEF::ELF::Parser::parse(input);
		if (!binary) elfbench::fail("LIEF failed to parse the in-memory ELF");
		return binary;
	}

	static BinaryPtr prepare_mutable(const std::vector<std::uint8_t> &input) {
		return parse(input);
	}

	static LIEF::ELF::Section &bench_section(LIEF::ELF::Binary &binary, std::uint64_t index) {
		const std::string name = ".bench." + std::to_string(index);
		LIEF::ELF::Section *section = binary.get_section(name);
		if (section == nullptr)
			elfbench::fail("missing section " + name);
		return *section;
	}

	static const LIEF::ELF::Section &bench_section(const LIEF::ELF::Binary &binary, std::uint64_t index) {
		const std::string name = ".bench." + std::to_string(index);
		const LIEF::ELF::Section *section = binary.get_section(name);
		if (section == nullptr)
			elfbench::fail("missing section " + name);
		return *section;
	}

	static std::uint64_t lookup_sections(LIEF::ELF::Binary &binary, const Config &cfg) {
		std::uint64_t value = 0;

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const std::string name = ".bench." + std::to_string(i);

			LIEF::ELF::Section *section = binary.get_section(name);

			if (section == nullptr)
				elfbench::fail("missing section " + name);

			value ^= elfbench::mix64(section->virtual_address() ^ section->size() ^ i);
		}

		return value;
	}

	static void remove_sections(LIEF::ELF::Binary &binary, const Config &cfg) {
		for (std::uint64_t i = cfg.sections; i-- != 0;) {
			binary.remove_section(".bench." + std::to_string(i), false);
		}
	}

	static void validate_removed(const LIEF::ELF::Binary &binary, const Config &cfg) {
		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const std::string name = ".bench." + std::to_string(i);

			if (binary.get_section(name) != nullptr) {
				elfbench::fail("section survived removal: " + name);
			}
		}
	}

	static std::vector<std::size_t> covering_load_segments(
		const LIEF::ELF::Binary  &binary,
		const LIEF::ELF::Section &section
	) {
		std::vector<std::size_t> result;
		std::size_t index = 0;

		const std::uint64_t section_begin = section.virtual_address();
		const std::uint64_t section_end   = section_begin + section.size();
		if (section_end < section_begin)
			elfbench::fail("section address overflow");

		for (const LIEF::ELF::Segment &segment : binary.segments()) {
			if (segment.type() == LIEF::ELF::Segment::TYPE::LOAD) {
				const std::uint64_t seg_begin = segment.virtual_address();
				const std::uint64_t seg_end   = seg_begin + segment.virtual_size();
				if (seg_end < seg_begin)
					elfbench::fail("segment address overflow");

				const bool covered = section.size() == 0
					? (seg_begin <= section_begin && section_begin < seg_end)
					: (seg_begin <= section_begin && section_end  <= seg_end);

				if (covered) result.push_back(index);
			}
			++index;
		}

		return result;
	}

	static void validate_fixture(const LIEF::ELF::Binary &binary, const Config &cfg) {
		std::vector<std::size_t> unique_segments;
		unique_segments.reserve(static_cast<std::size_t>(cfg.sections));

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const LIEF::ELF::Section &section = bench_section(binary, i);
			if (section.size() != cfg.section_size) {
				elfbench::fail(
					section.name() + " has size " +
					std::to_string(section.size()) +
					", expected " + std::to_string(cfg.section_size)
				);
			}
			if (section.virtual_address() == 0) {
				elfbench::fail(section.name() +
				               " is not allocated at a virtual address");
			}

			const std::vector<std::size_t> covering = covering_load_segments(binary, section);
			if (covering.size() != 1) {
				elfbench::fail(
					section.name() +
					" must be covered by exactly one PT_LOAD, got " +
					std::to_string(covering.size())
				);
			}
			unique_segments.push_back(covering.front());
		}

		std::sort(unique_segments.begin(), unique_segments.end());
		unique_segments.erase(
			std::unique(unique_segments.begin(), unique_segments.end()),
			unique_segments.end()
		);

		const std::size_t expected = cfg.topology == Topology::OneToN
			? 1
			: static_cast<std::size_t>(cfg.sections);
		if (unique_segments.size() != expected) {
			elfbench::fail(
				std::string("fixture topology mismatch: expected ") +
				std::to_string(expected) + " distinct PT_LOAD segment(s) covering .bench.*," +
				" got " + std::to_string(unique_segments.size())
			);
		}
	}

	static void replace_payloads(
		LIEF::ELF::Binary &binary,
		const Config &cfg,
		const std::vector<std::vector<std::uint8_t>> &payloads
	) {
		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			LIEF::ELF::Section &section = bench_section(binary, i);
			section.content(payloads[static_cast<std::size_t>(i)]);
			if (section.size() != cfg.section_size)
				elfbench::fail("LIEF changed section size during same-size payload replacement");
		}
	}

	static std::vector<std::uint8_t> serialize(LIEF::ELF::Binary &binary) {
		return binary.raw();
	}

	static void validate_payloads(
		const LIEF::ELF::Binary &binary,
		const Config &cfg,
		const std::vector<std::vector<std::uint8_t>> &payloads
	) {
		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const LIEF::ELF::Section &section = bench_section(binary, i);
			const auto content = section.content();
			const auto &expected = payloads[static_cast<std::size_t>(i)];
			if (content.size() != expected.size() ||
			    !std::equal(content.begin(), content.end(), expected.begin()))
			{
				elfbench::fail(section.name() + " payload mismatch after LIEF round trip");
			}
		}
	}

	static void create_workload(
		LIEF::ELF::Binary &binary,
		const Config &cfg,
		const std::vector<std::vector<std::uint8_t>> &payloads
	) {
		if (cfg.topology == Topology::OneToN) {
			elfbench::fail("LIEF create 1:N is unsupported by the current public API");
		}

		if (!binary.reserve_segments(static_cast<std::size_t>(cfg.sections))) {
			elfbench::fail("LIEF failed to reserve program headers");
		}

		if (binary.relocate_phdr_table(LIEF::ELF::Binary::PHDR_RELOC::BINARY_END) == 0) {
			elfbench::fail("LIEF failed to relocate PHDR table");
		}

		const std::uint64_t stride = elfbench::align_up(
			cfg.section_size,
			elfbench::CREATE_ALIGNMENT
		);

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			LIEF::ELF::Section section(
				".bench." + std::to_string(i),
				LIEF::ELF::Section::TYPE::PROGBITS
			);

			section.add(LIEF::ELF::Section::FLAGS::ALLOC);
			section.add(LIEF::ELF::Section::FLAGS::WRITE);

			section.virtual_address(elfbench::CREATE_LOAD_BASE + i * stride);
			section.alignment      (elfbench::CREATE_ALIGNMENT);
			section.entry_size     (0);
			section.link           (0);
			section.information    (0);
			section.content        (payloads[static_cast<std::size_t>(i)]);

			LIEF::ELF::Section *added = binary.add(section, /*loaded=*/true);

			if (added == nullptr)
				elfbench::fail("LIEF failed to add loaded section");

			// LIEF rounds loaded sections to the page/segment size
			added->size(cfg.section_size);
		}
	}

	static std::uint64_t consume(const LIEF::ELF::Binary &binary) {
		return static_cast<std::uint64_t>(binary.sections().size()) ^
		      (static_cast<std::uint64_t>(binary.segments().size()) << 32);
	}
};

} // namespace

int main(int argc, char **argv) {
	return elfbench::benchmark_main<LIEFAdapter>(argc, argv);
}
