#include "common.hpp"

#include <llvm/ADT/StringRef.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFTypes.h>
#include <llvm/Support/Error.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

using elfbench::Config;
using elfbench::Topology;

using ELFType = llvm::object::ELF64LE;
using ELFFile = llvm::object::ELF64LEFile;

struct LLVMBinary {
	ELFFile file;
	ELFType::ShdrRange sections;
	ELFType::PhdrRange segments;
	llvm::StringRef    section_names;

	LLVMBinary(
		ELFFile          &&file_,
		ELFType::ShdrRange sections_,
		ELFType::PhdrRange segments_,
		llvm::StringRef    section_names_
	)
		: file(std::move(file_))
		, sections(sections_)
		, segments(segments_)
		, section_names(section_names_) {}
};

struct LLVMAdapter {
	using BinaryPtr = std::unique_ptr<LLVMBinary>;

	static const char *name() {
		return "llvm";
	}

	static BinaryPtr parse(const std::vector<std::uint8_t> &input) {
		if (input.size() < llvm::ELF::EI_NIDENT)
			elfbench::fail("LLVM input is smaller than ELF identification");

		if (std::memcmp(input.data(), llvm::ELF::ElfMagic, 4) != 0)
			elfbench::fail("LLVM input does not have ELF magic");

		if (input[llvm::ELF::EI_CLASS] != llvm::ELF::ELFCLASS64)
			elfbench::fail("LLVM benchmark requires ELFCLASS64");

		if (input[llvm::ELF::EI_DATA] != llvm::ELF::ELFDATA2LSB)
			elfbench::fail("LLVM benchmark requires little-endian ELF");

		const llvm::StringRef bytes(
			reinterpret_cast<const char *>(input.data()),
			input.size()
		);

		auto file_or_error = ELFFile::create(bytes);
		if (!file_or_error) {
			elfbench::fail(
				"LLVM failed to create ELF view: " +
				llvm::toString(file_or_error.takeError())
			);
		}

		ELFFile file = std::move(*file_or_error);

		auto sections_or_error = file.sections();
		if (!sections_or_error) {
			elfbench::fail(
				"LLVM failed to read section table: " +
				llvm::toString(sections_or_error.takeError())
			);
		}

		const ELFType::ShdrRange sections = *sections_or_error;

		auto segments_or_error = file.program_headers();
		if (!segments_or_error) {
			elfbench::fail(
				"LLVM failed to read program header table: " +
				llvm::toString(segments_or_error.takeError())
			);
		}

		const ELFType::PhdrRange segments = *segments_or_error;

		auto names_or_error = file.getSectionStringTable(sections);
		if (!names_or_error) {
			elfbench::fail(
				"LLVM failed to read section-name string table: " +
				llvm::toString(names_or_error.takeError())
			);
		}

		return std::make_unique<LLVMBinary>(
			std::move(file),
			sections,
			segments,
			*names_or_error
		);
	}

	static BinaryPtr prepare_mutable(const std::vector<std::uint8_t> &) {
		unsupported("mutable operations");
	}

	static const ELFType::Shdr *find_section(const LLVMBinary &binary, llvm::StringRef target) {
		for (const ELFType::Shdr &section : binary.sections) {
			auto name_or_error = binary.file.getSectionName(
				section,
				binary.section_names
			);

			if (!name_or_error) {
				elfbench::fail(
					"LLVM failed to resolve section name: " +
					llvm::toString(name_or_error.takeError())
				);
			}

			if (*name_or_error == target) return &section;
		}

		return nullptr;
	}

	static const ELFType::Shdr &bench_section(const LLVMBinary &binary, std::uint64_t index) {
		const std::string name = ".bench." + std::to_string(index);

		const ELFType::Shdr *section = find_section(binary, name);

		if (section == nullptr)
			elfbench::fail("missing section " + name);

		return *section;
	}

	static std::vector<std::size_t> covering_load_segments(
		const LLVMBinary    &binary,
		const ELFType::Shdr &section
	) {
		std::vector<std::size_t> result;

		const std::uint64_t section_begin = static_cast<std::uint64_t>(section.sh_addr);
		const std::uint64_t section_size  = static_cast<std::uint64_t>(section.sh_size);

		const std::uint64_t section_end = section_begin + section_size;

		if (section_end < section_begin)
			elfbench::fail("section address overflow");

		std::size_t index = 0;

		for (const ELFType::Phdr &segment : binary.segments) {
			if (static_cast<std::uint32_t>(segment.p_type) == llvm::ELF::PT_LOAD) {
				const std::uint64_t segment_begin = static_cast<std::uint64_t>(
					segment.p_vaddr
				);

				const std::uint64_t segment_size = static_cast<std::uint64_t>(
					segment.p_memsz
				);

				const std::uint64_t segment_end = segment_begin + segment_size;

				if (segment_end < segment_begin)
					elfbench::fail("segment address overflow");

				const bool covered = section_size == 0
					? (segment_begin <= section_begin &&
					   section_begin < segment_end)
					: (segment_begin <= section_begin &&
					   section_end <= segment_end);

				if (covered) result.push_back(index);
			}

			++index;
		}

		return result;
	}

	static void validate_fixture(const LLVMBinary &binary, const Config &cfg) {
		std::vector<std::size_t> unique_segments;
		unique_segments.reserve(static_cast<std::size_t>(cfg.sections));

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const ELFType::Shdr &section = bench_section(binary, i);

			const std::uint64_t size = static_cast<std::uint64_t>(section.sh_size);

			if (size != cfg.section_size) {
				elfbench::fail(
					".bench." + std::to_string(i) + " has size " +
					std::to_string(size) + ", expected " +
					std::to_string(cfg.section_size)
				);
			}

			if (static_cast<std::uint64_t>(section.sh_addr) == 0) {
				elfbench::fail(
					".bench." + std::to_string(i) +
					" is not allocated at a virtual address"
				);
			}

			const std::vector<std::size_t> covering =
				covering_load_segments(binary, section);

			if (covering.size() != 1) {
				elfbench::fail(
					".bench." + std::to_string(i) +
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
				"fixture topology mismatch: expected " +
				std::to_string(expected) +
				" distinct PT_LOAD segment(s) covering .bench.*, got " +
				std::to_string(unique_segments.size())
			);
		}
	}

	static std::uint64_t lookup_sections(const LLVMBinary &binary, const Config &cfg) {
		std::uint64_t value = 0;

		// no public name->section index
		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const std::string name = ".bench." + std::to_string(i);

			const ELFType::Shdr *section = find_section(binary, name);

			if (section == nullptr) elfbench::fail("missing section " + name);

			value ^= elfbench::mix64(
				static_cast<std::uint64_t>(section->sh_addr) ^
				static_cast<std::uint64_t>(section->sh_size) ^
				i
			);
		}

		return value;
	}

	static void replace_payloads(
		LLVMBinary &,
		const Config &,
		const std::vector<std::vector<std::uint8_t>> &
	) {
		unsupported("write");
	}

	static void remove_sections(LLVMBinary &, const Config &) {
		unsupported("remove");
	}

	static void create_workload(
		LLVMBinary &,
		const Config &,
		const std::vector<std::vector<std::uint8_t>> &
	) {
		unsupported("create");
	}

	static std::vector<std::uint8_t> serialize(LLVMBinary &) {
		unsupported("serialization");
	}

	static void validate_payloads(
		const LLVMBinary &,
		const Config &,
		const std::vector<std::vector<std::uint8_t>> &
	) {
		unsupported("write validation");
	}

	static void validate_removed(const LLVMBinary &, const Config &) {
		unsupported("remove validation");
	}

	static std::uint64_t consume(const LLVMBinary &binary) {
		return static_cast<std::uint64_t>(binary.sections.size()) ^
		      (static_cast<std::uint64_t>(binary.segments.size()) << 32) ^
		       static_cast<std::uint64_t>(binary.file.getBufSize());
	}

private:
	[[noreturn]] static void unsupported(const char *operation) {
		elfbench::fail(
			std::string("LLVM ELFFile frontend does not support ") +
			operation
		);
	}
};

} // namespace

int main(int argc, char **argv) {
	return elfbench::benchmark_main<LLVMAdapter>(argc, argv);
}
