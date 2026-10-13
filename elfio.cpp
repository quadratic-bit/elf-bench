#include "common.hpp"

#include <elfio/elfio.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <istream>
#include <memory>
#include <streambuf>
#include <string>
#include <vector>
#include <limits>
#include <ostream>

namespace {

using elfbench::Config;
using elfbench::Topology;

class MemoryInputStreamBuf final : public std::streambuf {
public:
	MemoryInputStreamBuf(const std::uint8_t *data, std::size_t size) {
		char *begin = const_cast<char *>(reinterpret_cast<const char *>(data));
		begin_ = begin;
		end_   = begin + size;
		setg(begin_, begin_, end_);
	}

protected:
	pos_type seekoff(
		off_type offset,
		std::ios_base::seekdir  direction,
		std::ios_base::openmode which
	) override {
		if ((which & std::ios_base::in) == 0)
			return pos_type(off_type(-1));

		char *base = nullptr;
		if (direction == std::ios_base::beg) {
			base = begin_;
		} else if (direction == std::ios_base::cur) {
			base = gptr();
		} else if (direction == std::ios_base::end) {
			base = end_;
		} else {
			return pos_type(off_type(-1));
		}

		const off_type base_offset = static_cast<off_type>(base - begin_);
		const off_type size        = static_cast<off_type>(end_ - begin_);
		if ((offset < 0 && -offset > base_offset) ||
		    (offset > 0 && offset > size - base_offset)) {
			return pos_type(off_type(-1));
		}

		const off_type target_offset = base_offset + offset;
		setg(begin_, begin_ + target_offset, end_);
		return pos_type(target_offset);
	}

	pos_type seekpos(pos_type position, std::ios_base::openmode which) override {
		if ((which & std::ios_base::in) == 0)
			return pos_type(off_type(-1));

		const off_type target = static_cast<off_type>(position);
		const off_type size   = static_cast<off_type>(end_ - begin_);
		if (target < 0 || target > size)
			return pos_type(off_type(-1));

		setg(begin_, begin_ + target, end_);
		return position;
	}

private:
	char *begin_ = nullptr;
	char *end_   = nullptr;
};

class MemoryIStream final : public std::istream {
public:
	MemoryIStream(const std::uint8_t *data, std::size_t size)
		: std::istream(nullptr), buffer_(data, size) {
			rdbuf(&buffer_);
			clear();
		}

private:
	MemoryInputStreamBuf buffer_;
};

class MemoryOutputStreamBuf final : public std::streambuf {
public:
	std::vector<std::uint8_t> take() {
		return std::move(data_);
	}

protected:
	std::streamsize xsputn(const char_type *source, std::streamsize count) override {
		if (count <= 0)
			return 0;

		const auto size = static_cast<std::uintmax_t>(count);
		if (size > std::numeric_limits<std::size_t>::max() - position_)
			return 0;

		const std::size_t end = position_ + static_cast<std::size_t>(size);

		if (end > data_.size()) data_.resize(end, std::uint8_t{0});

		std::memcpy(data_.data() + position_, source, static_cast<std::size_t>(size));

		position_ = end;
		return count;
	}

	int_type overflow(int_type value) override {
		if (traits_type::eq_int_type(value, traits_type::eof()))
			return traits_type::not_eof(value);

		const char_type character = traits_type::to_char_type(value);
		return xsputn(&character, 1) == 1 ? value : traits_type::eof();
	}

	pos_type seekoff(
		off_type offset,
		std::ios_base::seekdir direction,
		std::ios_base::openmode which
	) override {
		if ((which & std::ios_base::out) == 0)
			return invalid_position();

		std::size_t base = 0;

		if (direction == std::ios_base::beg) {
			base = 0;
		} else if (direction == std::ios_base::cur) {
			base = position_;
		} else if (direction == std::ios_base::end) {
			base = data_.size();
		} else {
			return invalid_position();
		}

		return seek_from(base, offset);
	}

	pos_type seekpos(pos_type position, std::ios_base::openmode which) override {
		if ((which & std::ios_base::out) == 0)
			return invalid_position();

		const off_type offset = static_cast<off_type>(position);
		if (offset < 0)
			return invalid_position();

		return seek_from(0, offset);
	}

private:
	static pos_type invalid_position() {
		return pos_type(off_type(-1));
	}

	pos_type seek_from(std::size_t base, off_type offset) {
		std::size_t target = 0;

		if (offset >= 0) {
			const auto amount = static_cast<std::uintmax_t>(offset);

			if (amount > std::numeric_limits<std::size_t>::max() - base)
				return invalid_position();

			target = base + static_cast<std::size_t>(amount);
		} else {
			if (offset == std::numeric_limits<off_type>::min())
				return invalid_position();

			const auto amount = static_cast<std::uintmax_t>(-offset);
			if (amount > base)
				return invalid_position();

			target = base - static_cast<std::size_t>(amount);
		}

		if (static_cast<std::uintmax_t>(target) >
		    static_cast<std::uintmax_t>(std::numeric_limits<off_type>::max())
		) {
			return invalid_position();
		}

		position_ = target;
		return pos_type(static_cast<off_type>(position_));
	}

	std::vector<std::uint8_t> data_;
	std::size_t position_ = 0;
};

class MemoryOStream final : public std::ostream {
public:
	MemoryOStream() : std::ostream(nullptr) {
		rdbuf(&buffer_);
		clear();
	}

	std::vector<std::uint8_t> take() {
		return buffer_.take();
	}

private:
	MemoryOutputStreamBuf buffer_;
};

struct ELFIOAdapter {
	using BinaryPtr = std::unique_ptr<ELFIO::elfio>;

	static const char *name() {
		return "elfio";
	}

	static BinaryPtr parse(const std::vector<std::uint8_t> &input) {
		auto binary = std::make_unique<ELFIO::elfio>();
		MemoryIStream stream(input.data(), input.size());
		if (!binary->load(stream, /*is_lazy=*/false))
			elfbench::fail("ELFIO failed to parse the in-memory ELF");
		return binary;
	}

	static ELFIO::section &bench_section(ELFIO::elfio &binary, std::uint64_t index) {
		const std::string name = ".bench." + std::to_string(index);
		ELFIO::section *section = binary.sections[name];
		if (section != nullptr)
			return *section;
		elfbench::fail("missing section " + name);
	}

	static const ELFIO::section &bench_section(
		const ELFIO::elfio &binary,
		std::uint64_t index
	) {
		const std::string name = ".bench." + std::to_string(index);
		const ELFIO::section *section = binary.sections[name];
		if (section != nullptr)
			return *section;
		elfbench::fail("missing section " + name);
	}

	static BinaryPtr prepare_mutable(const std::vector<std::uint8_t> &input) {
		return parse(input);
	}

	static std::uint64_t lookup_sections(ELFIO::elfio &binary, const Config &cfg) {
		std::uint64_t value = 0;

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const std::string name = ".bench." + std::to_string(i);

			ELFIO::section *section = binary.sections[name];

			if (section == nullptr)
				elfbench::fail("missing section " + name);

			value ^= elfbench::mix64(section->get_address() ^ section->get_size() ^ i);
		}

		return value;
	}

	static void remove_sections(ELFIO::elfio &binary, const Config &cfg) {
		elfbench::fail("ELFIO remove unsupported");
	}

	static void validate_removed(const ELFIO::elfio &binary, const Config &cfg) {
		elfbench::fail("ELFIO remove unsupported");
	}

	static std::vector<std::size_t> covering_load_segments(
		const ELFIO::elfio   &binary,
		const ELFIO::section &section
	) {
		std::vector<std::size_t> result;
		std::size_t index = 0;

		const std::uint64_t section_begin = section.get_address();
		const std::uint64_t section_size  = section.get_size();
		const std::uint64_t section_end   = section_begin + section_size;
		if (section_end < section_begin)
			elfbench::fail("section address overflow");

		for (const auto &segment_ptr : binary.segments) {
			const ELFIO::segment *seg = segment_ptr.get();
			if (seg != nullptr && seg->get_type() == ELFIO::PT_LOAD) {
				const std::uint64_t seg_begin = seg->get_virtual_address();
				const std::uint64_t seg_end   = seg_begin + seg->get_memory_size();
				if (seg_end < seg_begin)
					elfbench::fail("segment address overflow");

				const bool covered = section_size == 0
					? (seg_begin <= section_begin && section_begin < seg_end)
					: (seg_begin <= section_begin && section_end <= seg_end);
				if (covered)
					result.push_back(index);
			}
			++index;
		}

		return result;
	}

	static void validate_fixture(const ELFIO::elfio &binary, const Config &cfg) {
		std::vector<std::size_t> unique_segments;
		unique_segments.reserve(static_cast<std::size_t>(cfg.sections));

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const ELFIO::section &section = bench_section(binary, i);
			if (section.get_size() != cfg.section_size) {
				elfbench::fail(
					section.get_name() + " has size " +
					std::to_string(section.get_size()) +
					", expected " + std::to_string(cfg.section_size)
				);
			}
			if (section.get_address() == 0)
				elfbench::fail(section.get_name() +
				               " is not allocated at a virtual address");

			const std::vector<std::size_t> covering = covering_load_segments(binary, section);
			if (covering.size() != 1) {
				elfbench::fail(
					section.get_name() +
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
				std::to_string(expected) +
				" distinct PT_LOAD segment(s) covering .bench.*," +
				" got " + std::to_string(unique_segments.size())
			);
		}
	}

	static void replace_payloads(
		ELFIO::elfio &binary,
		const Config &cfg,
		const std::vector<std::vector<std::uint8_t>> &payloads
	) {
		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			ELFIO::section &section = bench_section(binary, i);
			const auto &payload = payloads[static_cast<std::size_t>(i)];
			section.set_data(
				reinterpret_cast<const char *>(payload.data()),
				static_cast<ELFIO::Elf_Xword>(payload.size())
			);
			if (section.get_size() != cfg.section_size) {
				elfbench::fail("ELFIO changed section size while payload replace");
			}
		}
	}

	static std::vector<std::uint8_t> serialize(ELFIO::elfio &binary) {
		MemoryOStream stream;

		if (!binary.save(stream) || !stream)
			elfbench::fail("ELFIO failed to serialize the ELF into memory");

		return stream.take();
	}

	static void validate_payloads(
		const ELFIO::elfio &binary,
		const Config &cfg,
		const std::vector<std::vector<std::uint8_t>> &payloads
	) {
		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const ELFIO::section &section = bench_section(binary, i);
			const auto &expected = payloads[static_cast<std::size_t>(i)];
			const char *data = section.get_data();
			if (data == nullptr || section.get_size() != expected.size() ||
			    std::memcmp(data, expected.data(), expected.size()) != 0) {
				elfbench::fail(section.get_name() + " payload mismatch");
			}
		}
	}

	static void create_workload(
		ELFIO::elfio &binary,
		const Config &cfg,
		const std::vector<std::vector<std::uint8_t>> &payloads
	) {
		const std::uint64_t stride = elfbench::align_up(
			cfg.section_size,
			elfbench::CREATE_ALIGNMENT
		);

		std::vector<ELFIO::section *> sections;
		sections.reserve(static_cast<std::size_t>(cfg.sections));

		for (std::uint64_t i = 0; i < cfg.sections; ++i) {
			const std::uint64_t address =
				elfbench::CREATE_LOAD_BASE + i * stride;

			ELFIO::section *section = binary.sections.add(
				".bench." + std::to_string(i)
			);

			if (section == nullptr)
				elfbench::fail("ELFIO failed to add section");

			const auto &payload =
				payloads[static_cast<std::size_t>(i)];

			section->set_type      (ELFIO::SHT_PROGBITS);
			section->set_flags     (ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE);
			section->set_address   (address);
			section->set_addr_align(elfbench::CREATE_ALIGNMENT);
			section->set_entry_size(0);
			section->set_link      (0);
			section->set_info      (0);
			section->set_data(
				reinterpret_cast<const char *>(payload.data()),
				static_cast<ELFIO::Elf_Xword>(payload.size())
			);

			sections.push_back(section);
		}

		auto configure_segment = [](ELFIO::segment &segment, std::uint64_t address) {
			segment.set_type            (ELFIO::PT_LOAD);
			segment.set_flags           (ELFIO::PF_R | ELFIO::PF_W);
			segment.set_virtual_address (address);
			segment.set_physical_address(address);
			segment.set_align           (elfbench::CREATE_ALIGNMENT);
		};

		if (cfg.topology == Topology::OneToN) {
			ELFIO::segment *segment = binary.segments.add();

			if (segment == nullptr)
				elfbench::fail("ELFIO failed to add PT_LOAD");

			configure_segment(*segment, elfbench::CREATE_LOAD_BASE);

			for (ELFIO::section *section : sections)
				segment->add_section(section, elfbench::CREATE_ALIGNMENT);
		} else {
			for (ELFIO::section *section : sections) {
				ELFIO::segment *segment = binary.segments.add();

				if (segment == nullptr)
					elfbench::fail("ELFIO failed to add PT_LOAD");

				configure_segment(*segment, section->get_address());

				segment->add_section(section, elfbench::CREATE_ALIGNMENT);
			}
		}
	}

	static std::uint64_t consume(const ELFIO::elfio &binary) {
		return static_cast<std::uint64_t>(binary.sections.size()) ^
		      (static_cast<std::uint64_t>(binary.segments.size()) << 32);
	}
};

} // namespace

int main(int argc, char **argv) {
	return elfbench::benchmark_main<ELFIOAdapter>(argc, argv);
}
