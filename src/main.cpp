#include <qpl/qpl.hpp>

namespace data {
	qpl::file_encrypter builder;
	bool use_encryption = true;
}

qpl::size get_input_size(qpl::size total_size) {
	qpl::size result = 0u;
	constexpr auto check_count = [](qpl::size split_size, qpl::size total_size, std::string byte_string) {
		auto file_count = (total_size - 1) / split_size + 1;
		if (file_count > 100) {
			while (true) {
				qpl::print("are you sure you want to create > ", file_count, " files? (y/n) > ");

				auto input = qpl::get_input();
				if (qpl::string_equals_ignore_case(input, "y")) {
					return;
				}
				else if (qpl::string_equals_ignore_case(input, "n")) {
					qpl::println();
					qpl::println_repeat("-", 100);
					qpl::println();
					get_input_size(total_size);
				}
			}
		}
	};

	while (true) {
		qpl::print("enter split size [enter to ignore] > ");

		auto input = qpl::get_input();
		if (input.empty()) {
			result = qpl::size_max;
			break;
		}
		auto split = qpl::split_string_digit_alpha(input);
		if (split.size() == 2u) {

			constexpr auto by = 1.0;
			constexpr auto bi = 3.0;

			auto amount = qpl::f64_cast(split[0u]);
			auto type = split[1u];

			if (qpl::string_equals_ignore_case(type, "b")) {
				result = qpl::size_cast(amount);
			}
			else if (qpl::string_equals_ignore_case(type, "kb")) {
				result = qpl::size_cast(amount * qpl::pow(10.0, bi * 1.0));
			}
			else if (qpl::string_equals_ignore_case(type, "kib")) {
				result = qpl::size_cast(amount * qpl::pow(1024.0, by * 1.0));
			}
			else if (qpl::string_equals_ignore_case(type, "mb")) {
				result = qpl::size_cast(amount * qpl::pow(10.0, bi * 2.0));
			}
			else if (qpl::string_equals_ignore_case(type, "mib")) {
				result = qpl::size_cast(amount * qpl::pow(1024.0, by * 2.0));
			}
			else if (qpl::string_equals_ignore_case(type, "gb")) {
				result = qpl::size_cast(amount * qpl::pow(10.0, bi * 3.0));
			}
			else if (qpl::string_equals_ignore_case(type, "gib")) {
				result = qpl::size_cast(amount * qpl::pow(1024.0, by * 3.0));
			}
			else if (qpl::string_equals_ignore_case(type, "tb")) {
				result = qpl::size_cast(amount * qpl::pow(10.0, bi * 4.0));
			}
			else if (qpl::string_equals_ignore_case(type, "tib")) {
				result = qpl::size_cast(amount * qpl::pow(1024.0, by * 4.0));
			}
			else {
				return get_input_size(total_size);
			}

			check_count(result, total_size, qpl::to_string(amount, type));
			
			break;
		}
		else if (split.size() == 1u) {
			result = qpl::size_cast(split[0u]);
			check_count(result, total_size, qpl::to_string(result, "b"));
			break;
		}
	}
	return result;
}

int main(int argc, char** argv) try {

	std::vector<std::string> args(argc - 1);
	for (qpl::i32 i = 0; i < argc - 1; ++i) {
		args[i] = argv[i + 1];
	}

	if (args.empty()) {
		qpl::println("drag a folder or file/s on this executable.");
		qpl::system_pause();
		return 0;
	}
	else {

		std::string encryption_way;
		data::use_encryption = true;

		while (true) {
			qpl::print("encrypt or decrypt? (e/d) > ");
			encryption_way = qpl::get_input();
			if (qpl::string_equals_ignore_case(encryption_way, "e")) {
				data::use_encryption = true;
				break;
			}
			else if (qpl::string_equals_ignore_case(encryption_way, "d")) {
				data::use_encryption = false;
				break;
			}
		}

		qpl::println();
		qpl::println_repeat("-", 100);
		qpl::println();
		qpl::print("input encryption key > ");
		auto key = qpl::get_hidden_input();


		qpl::println();
		qpl::println_repeat("-", 100);
		qpl::println();
		qpl::aes::mode mode = qpl::aes::mode::_128;
		while (true) {
			qpl::print("which AES bit size to use? [enter to use 128] (128/192/256) > ");
			auto input = qpl::get_input();

			if (input.empty() || input == "128") {
				mode = qpl::aes::mode::_128;
				break;
			}
			else if (input == "192") {
				mode = qpl::aes::mode::_192;
				break;
			}
			else if (input == "256") {
				mode = qpl::aes::mode::_256;
				break;
			}
		}

		qpl::println();
		qpl::println_repeat("-", 100);
		qpl::println();
		qpl::size split_size = qpl::size_max;
		if (data::use_encryption) {
			qpl::size file_size = 0u;
			for (auto& arg : args) {
				file_size += qpl::filesys::path(arg).file_size_recursive();
			}
			split_size = get_input_size(file_size);
		}
		qpl::clock clock;
		for (auto &arg : args) {
			data::builder.add(arg);
		}

		std::string encryption_name = "";
		if (data::use_encryption) {
			qpl::println();
			qpl::println_repeat("-", 100);
			qpl::println();

			encryption_name = data::builder.common_branch.get_full_name();
			qpl::print("output name? [enter to use \"", encryption_name, "\"] > ");
			auto input = qpl::get_input();
			if (!input.empty()) {
				encryption_name = input;
			}
		}

		if (data::use_encryption) {
			qpl::print("encrypting . . . ");
		}
		else {
			qpl::print("decrypting . . . ");
		}
		qpl::filesys::paths tree;
		if (data::use_encryption) {
			tree = data::builder.encrypt(key, encryption_name, mode, "", split_size);
		}
		else {
			tree = data::builder.decrypt(key, mode);
		}

		qpl::println("done. took ", clock.elapsed_str());
		tree.print_tree();

		qpl::println();
		qpl::println_repeat("-", 100);
		qpl::println();
		qpl::filesys::paths p;
		for (auto& i : args) {
			p.push_back(i);
		}
		p.print_tree();
		while (true) {
			if (p.size() == 1u) {
				qpl::print("\n ^ DELETE this original", data::use_encryption ? " " : " encrypted ", "file? [enter to ignore] (y/n) > ");
			}
			else {
				qpl::print("\n ^ DELETE these original", data::use_encryption ? " " : " encrypted ", "files ? [enter to ignore] (y / n) > ");
			}


			auto input = qpl::get_input();
			if (input.empty()) {
				break;
			}
			if (qpl::string_equals_ignore_case(input, "y")) {
				for (auto& i : args) {
					qpl::filesys::remove(i);
				}
				break;
			}
			else if (qpl::string_equals_ignore_case(input, "n")) {
				break;
			}
		}
	}
}
catch (std::exception& any) {

	if (!data::use_encryption) {
		qpl::println();
		qpl::println_repeat("-", 100);
		qpl::println();
		qpl::println("decryption FAILED. key was wrong.");
		qpl::println();
		qpl::println_repeat("-", 100);
		qpl::println();
	}
	else {
		qpl::println("caught exception:\n", any.what());
	}

	qpl::system_pause();
}