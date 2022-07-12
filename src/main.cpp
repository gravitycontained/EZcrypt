#include <qpl/qpl.hpp>

void gen_data() {

	auto p = qpl::filesys::get_current_location();

	for (qpl::u32 i = 0u; i < 10; ++i) {
		auto name = qpl::get_random_lowercase_uppercase_number_string(10);
		auto extension = qpl::get_random_lowercase_string(3);
		auto new_name = qpl::to_string(name, ".", extension);
		auto path = p.make_file(new_name);
		path.write(qpl::get_random_string(20));
	}
}

struct builder {
	qpl::filesys::paths paths;
	qpl::filesys::path common_branch;
	qpl::size additions = 0u;
	bool adding_parts = false;
	std::unordered_map<std::string, qpl::filesys::paths> part_paths;
	std::string keyword_string_part = "AES_PART";
	std::string keyword_string_enrypted = "ENCRYPTED";
	std::string keyword_string_derypted = "DECRYPTED";

	void clear() {
		this->paths.clear();
		this->additions = 0u;
		this->part_paths.clear();
	}
	void add(std::string path) {
		auto file_path = qpl::filesys::path(path);

		auto adding = file_path.get_file_extension().starts_with(this->keyword_string_part);

		if (adding) {
			if (!this->adding_parts) {
				++this->additions;
			}
			auto name = file_path.get_file_name();
			this->part_paths[name].push_back(file_path);
		}
		else {
			this->paths.push_back(path);
			++this->additions;
		}
		this->adding_parts = adding;


		if (this->common_branch.empty()) {
			this->common_branch = path;
		}
		else {
			this->common_branch = this->common_branch.get_common_branch(path);
		}

		if (file_path.is_file()) {
			return;
		}

		auto files = file_path.list_current_directory_tree();
		for (auto& i : files) {
			if (i.is_directory()) {
				if (i.string().back() != '/') {
					i.append("/");
				}
			}
			this->paths.push_back(i);

			if (this->common_branch.empty()) {
				this->common_branch = i;
			}
			else {
				this->common_branch = this->common_branch.get_common_branch(i);
			}
		}
	}
	std::string encrypted_string(const std::string& key, qpl::aes::mode mode) {
		if (this->paths.empty()) {
			return "";
		}
		if (this->additions == 1u) {
			if (this->paths.front().is_directory()) {
				this->common_branch.go_into(this->paths.front().get_name());
			}
		}
		auto common_size = this->common_branch.branch_size() - 1;

		qpl::save_state save_state;
		save_state.save(this->common_branch.string());
		save_state.save(this->paths.size());

		for (auto& i : this->paths) {
			save_state.save(i.string());
		}

		for (auto& i : this->paths) {
			if (i.is_file()) {
				save_state.save(i.read());
			}
		}

		this->clear();
		auto str = save_state.get_finalized_string();
		str = qpl::encrypted_keep_size(str, key, mode);
		return str;
	}
	qpl::filesys::paths encrypt(const std::string& key, std::string output_name, qpl::aes::mode mode, qpl::filesys::path destination_path = "", qpl::size split_size = qpl::size_max) {
		if (!destination_path.empty() && destination_path.string().back() != '/') {
			destination_path.append("/");
		}

		auto str = this->encrypted_string(key, mode);

		qpl::filesys::path encrypted_path = qpl::to_string(destination_path, output_name, '.', this->keyword_string_enrypted);

		qpl::size ctr = 0u;
		while (encrypted_path.exists()) {
			encrypted_path = qpl::to_string(destination_path, output_name, '.', this->keyword_string_enrypted, ctr);
			++ctr;
		}
		auto splits = qpl::split_string_every(str, split_size);
		if (splits.size() > 1) {
			
			auto log = std::log10(splits.size() - 1) + 1;
			for (qpl::size i = 0u; i < splits.size(); ++i) {
				auto part_string = qpl::to_string(".", this->keyword_string_part, qpl::prepended_to_string_to_fit(qpl::to_string(i), '0', qpl::size_cast(log)));
				auto path = encrypted_path;
				path.append(part_string);
				path.write(splits[i]);
			}
		}
		else {
			encrypted_path.write(str);
		}

		return this->paths;
	}
	qpl::filesys::paths decrypt(const std::string& key, qpl::aes::mode mode, qpl::filesys::path destination_path = "") const {
		if (!destination_path.empty() && destination_path.string().back() != '/') {
			destination_path.append("/");
		}
		qpl::filesys::paths tree;
		for (auto& path : this->paths) {
			auto string = path.read();
			this->internal_decrypt(string, key, mode, destination_path, tree);
		}
		for (auto& part : this->part_paths) {
			std::string string;

			const auto& paths = part.second;
			std::vector<std::pair<qpl::filesys::path, qpl::size>> sorted_parts(paths.size());
			for (qpl::size i = 0u; i < sorted_parts.size(); ++i) {
				auto n = qpl::size_cast(paths[i].get_file_extension().substr(this->keyword_string_part.length()));
				sorted_parts[i] = std::make_pair(paths[i], n);
			}
			qpl::sort(sorted_parts, [](const auto& a, const auto& b) {
				return a.second < b.second;
			});

			auto p = sorted_parts.size() == 1u ? "part" : "parts";
			qpl::println("loading ", sorted_parts.size(), " ", p, " . . . ");
			for (auto& file : sorted_parts) {
				qpl::println(file.first.string());
				string += file.first.read();
			}
			this->internal_decrypt(string, key, mode, destination_path, tree);
			qpl::println("done");
		}

		return tree;
	}
	private:
		void internal_decrypt(const std::string& string, const std::string& key, qpl::aes::mode mode, qpl::filesys::path destination_path, qpl::filesys::paths& tree) const {
			auto str = qpl::decrypted_keep_size(string, key, mode);

			qpl::save_state load_state;
			std::string s;
			load_state.set_string(str);
			load_state.load(s);
			qpl::filesys::path common = s;

			qpl::size size;
			load_state.load(size);
			qpl::filesys::paths loaded_paths;
			loaded_paths.resize(size);

			for (auto& i : loaded_paths) {
				std::string path_str;
				load_state.load(path_str);
				i = path_str;
			}

			std::string branch_name;
			auto split = qpl::split_string(common.get_full_name(), '.');

			branch_name = common.get_full_name();
			if (split.size() && split.back() == this->keyword_string_enrypted) {
				split.pop_back();
				branch_name = qpl::to_string_format("a.b", split);
			}
			branch_name += qpl::to_string('.', this->keyword_string_derypted);
			auto original_branch_name = branch_name;

			qpl::filesys::path decrypted_path = qpl::to_string(destination_path, branch_name, "/");

			qpl::size ctr = 0u;
			while (decrypted_path.exists()) {
				branch_name = qpl::to_string(original_branch_name, ctr);
				decrypted_path = qpl::to_string(destination_path, branch_name, "/");
				++ctr;
			}

			for (auto& i : loaded_paths) {
				decrypted_path = i;
				decrypted_path.set_branch(common.branch_size() - 1, branch_name);
				decrypted_path = qpl::to_string(destination_path, branch_name, "/", decrypted_path.subpath(common.branch_size() - 1));

				decrypted_path.ensure_branches_exist();

				if (i.is_file()) {
					std::string data_str;
					load_state.load(data_str);
					decrypted_path.write(data_str);
				}
				tree.push_back(decrypted_path);
			}
		}
};


namespace data {
	::builder builder;
	bool use_encryption = true;
}

void move() {
	qpl::filesys::copy_overwrite("C:/Users/Zugriffspunkt/source/repos/FileEncrypt/x64/Release/QPL.exe", "C:/Users/Zugriffspunkt/source/repos/FileEncrypt/QPL/QPL.exe");
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
				get_input_size(total_size);
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
		qpl::print("input encryption key > ");
		auto key = qpl::get_hidden_input();

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
		if (data::use_encryption) {
			auto tree = data::builder.encrypt(key, encryption_name, mode, "", split_size);
			tree.print_tree();
		}
		else {
			auto tree = data::builder.decrypt(key, mode);
			tree.print_tree();
		}

		qpl::println("done. took ", clock.elapsed_str());

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
				qpl::print("\n ^ DELETE these original", data::use_encryption ? " " : " encrypted ", "files ? [enter to ignore](y / n) > ");
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