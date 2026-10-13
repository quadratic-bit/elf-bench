#include <elfio/elfio.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::uint64_t LOAD_BASE = 0x100000000ULL;
constexpr std::uint64_t PAGE_SIZE = 0x1000ULL;

enum class Topology { OneToN, NToN };

struct Options {
	std::string   output_path;
	Topology      topology     = Topology::OneToN;
	std::uint64_t sections     = 0;
	std::uint64_t section_size = PAGE_SIZE;
};

[[noreturn]] void fail(const std::string &message) {
	throw std::runtime_error(message);
}

void usage(std::ostream &out, const char *program) {
	out
	<< "Usage:\n"
	<< "  " << program
	<< " <output-elf> --topology 1:N|N:N --sections N [--section-size N]\n\n"
	<< "Options:\n"
	<< "  --topology 1:N|N:N\n"
	<< "  --sections N\n"
	<< "  --section-size N     (default: 4K)\n"
	<< "  -h, --help\n\n"
	<< "Sizes accept K, M, G, and T suffixes.\n";
}

std::uint64_t parse_number(const char *text, bool scaled) {
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

Options parse_args(int argc, char **argv) {
	if (argc == 2 && (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0)) {
		usage(std::cout, argv[0]);
		std::exit(0);
	}

	if (argc < 2) {
		usage(std::cerr, argv[0]);
		fail("missing output ELF");
	}

	Options options;
	options.output_path = argv[1];

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

		if (option == "--topology") {
			if (std::strcmp(value, "1:N") == 0 || std::strcmp(value, "1:n") == 0) {
				options.topology = Topology::OneToN;
			} else if (std::strcmp(value, "N:N") == 0 ||
			           std::strcmp(value, "n:n") == 0) {
				options.topology = Topology::NToN;
			} else {
				fail("--topology must be 1:N or N:N");
			}
			have_topology = true;
		} else if (option == "--sections") {
			options.sections = parse_number(value, false);
			have_sections = true;
		} else if (option == "--section-size") {
			options.section_size = parse_number(value, true);
		} else {
			fail("unknown option: " + std::string(option));
		}
	}

	if (!have_topology)
		fail("missing --topology");
	if (!have_sections)
		fail("missing --sections");
	if (options.sections == 0 || options.section_size == 0)
		fail("sections and section-size must be nonzero");
	if (options.section_size > std::numeric_limits<std::size_t>::max())
		fail("section-size does not fit size_t");
	if (options.sections > std::numeric_limits<ELFIO::Elf_Half>::max() - 2)
		fail("too many sections for this fixture generator");

	return options;
}

std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
	if (value > std::numeric_limits<std::uint64_t>::max() - (alignment - 1))
		fail("alignment overflow");
	return (value + alignment - 1) & ~(alignment - 1);
}

void fill_payload(std::vector<std::uint8_t> &payload, std::uint64_t section_index) {
	std::uint64_t state = 0x6767676767676767ULL ^ (section_index * 0x9e3779b97f4a7c15ULL);

	for (std::size_t i = 0; i < payload.size(); ++i) {
		state ^= state >> 12;
		state ^= state << 25;
		state ^= state >> 27;
		payload[i] = static_cast<std::uint8_t>(state >> 56);
	}
}

void configure_segment(ELFIO::segment &segment, std::uint64_t address) {
	segment.set_type            (ELFIO::PT_LOAD);
	segment.set_flags           (ELFIO::PF_R | ELFIO::PF_W);
	segment.set_virtual_address (address);
	segment.set_physical_address(address);
	segment.set_align           (PAGE_SIZE);
}

void make_fixture(const Options &options) {
	ELFIO::elfio writer;
	writer.create         (ELFIO::ELFCLASS64, ELFIO::ELFDATA2LSB);
	writer.set_os_abi     (ELFIO::ELFOSABI_LINUX);
	writer.set_abi_version(0);
	writer.set_type       (ELFIO::ET_EXEC);
	writer.set_machine    (ELFIO::EM_X86_64);
	writer.set_flags      (0);

	const std::uint64_t stride = align_up(options.section_size, PAGE_SIZE);
	if (options.sections - 1 >
		(std::numeric_limits<std::uint64_t>::max() - LOAD_BASE) / stride) {
		fail("section address range overflows uint64_t");
	}

	std::vector<std::vector<std::uint8_t>> payloads;
	payloads.reserve(static_cast<std::size_t>(options.sections));

	std::vector<ELFIO::section *> sections;
	sections.reserve(static_cast<std::size_t>(options.sections));

	for (std::uint64_t i = 0; i < options.sections; ++i) {
		payloads.emplace_back(static_cast<std::size_t>(options.section_size));
		fill_payload(payloads.back(), i);

		ELFIO::section *section = writer.sections.add(
			".bench." + std::to_string(i)
		);
		if (section == nullptr)
			fail("failed to create .bench section");

		const std::uint64_t address = LOAD_BASE + i * stride;
		section->set_type      (ELFIO::SHT_PROGBITS);
		section->set_flags     (ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE);
		section->set_address   (address);
		section->set_addr_align(PAGE_SIZE);
		section->set_entry_size(0);
		section->set_link      (0);
		section->set_info      (0);
		section->set_data(
			reinterpret_cast<const char *>(payloads.back().data()),
			static_cast<ELFIO::Elf_Xword> (payloads.back().size())
		);

		sections.push_back(section);
	}

	writer.set_entry(LOAD_BASE);

	if (options.topology == Topology::OneToN) {
		ELFIO::segment *segment = writer.segments.add();
		if (segment == nullptr)
			fail("failed to create PT_LOAD segment");

		configure_segment(*segment, LOAD_BASE);
		for (ELFIO::section *section : sections)
			segment->add_section(section, PAGE_SIZE);
	} else {
		for (std::size_t i = 0; i < sections.size(); ++i) {
			ELFIO::segment *segment = writer.segments.add();
			if (segment == nullptr)
				fail("failed to create PT_LOAD segment");

			configure_segment(*segment, sections[i]->get_address());
			segment->add_section(sections[i], PAGE_SIZE);
		}
	}

	if (!writer.save(options.output_path))
		fail("failed to save fixture: " + options.output_path);
}

const char *topology_name(Topology topology) {
	return topology == Topology::OneToN ? "1:N" : "N:N";
}

} // namespace

int main(int argc, char **argv) {
	try {
		const Options options = parse_args(argc, argv);
		make_fixture(options);

		std::cout
			<< "created "        << options.output_path
			<< ", topology="     << topology_name(options.topology)
			<< ", sections="     << options.sections
			<< ", section_size=" << options.section_size
			<< '\n';
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "error: " << error.what() << '\n';
		return 1;
	}
}
