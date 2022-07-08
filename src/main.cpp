#include <qpl/qpl.hpp>

void encrypt(std::string path, const std::string& key) {
	qpl::filesys::path original_path = path;
	qpl::filesys::path control_path = path;

	if (control_path.is_directory()) {
		auto name = control_path.get_branch_at(control_path.branch_size() - 1).get_name();

		control_path.go_directory_back();
		qpl::filesys::path encrypted_path = qpl::to_string(name, ".encrypted/");
		qpl::size ctr = 0u;
		while (encrypted_path.exists()) {
			encrypted_path = qpl::to_string(name, ".encrypted", ctr, "/");
			++ctr;
		}
		control_path.go_into(encrypted_path);
		control_path.ensure_branches_exist();

		auto files = original_path.list_current_directory_tree();
		for (auto& f : files) {
			auto encrypted = f;
			encrypted.set_branch(original_path.branch_size() - 1, encrypted_path);
			encrypted.ensure_branches_exist();
			f.encrypt(encrypted, key);
		}
	}
	else if (control_path.is_file()) {
		auto parent = control_path.get_parent_branch();

		qpl::filesys::path encrypted_path = qpl::to_string(parent, control_path.get_file_name(), ".encrypted.", control_path.get_extension());

		qpl::size ctr = 0u;
		while (encrypted_path.exists()) {
			encrypted_path = qpl::to_string(parent, control_path.get_file_name(), ".encrypted", ctr, ".", control_path.get_extension());
			++ctr;
		}

		control_path.encrypt(encrypted_path, key);
	}
}

void decrypt(std::string path, const std::string& key) {
	qpl::filesys::path original_path = path;
	qpl::filesys::path control_path = path;

	if (control_path.is_directory()) {
		auto parent = control_path.get_parent_branch();

		auto name = control_path.get_directory_name();
		auto split = qpl::split_string(control_path.get_directory_name(), '.');

		if (split.size() && split.back() == "encrypted") {
			split.pop_back();
			name = qpl::to_string_format("a.b", split);
		}
		name += ".decrypted";

		qpl::filesys::path decrypted_path = qpl::to_string(parent, name, "/");

		qpl::size ctr = 0u;
		while (decrypted_path.exists()) {
			decrypted_path = qpl::to_string(parent, name, ctr, "/");
			++ctr;
		}

		control_path = decrypted_path;
		control_path.ensure_branches_exist();

		control_path.go_directory_back();
		control_path.go_into_directory(decrypted_path.get_directory_name());

		auto files = original_path.list_current_directory_tree();
		for (auto& f : files) {
			auto decrypted = f;
			decrypted.set_branch(original_path.branch_size() - 1, decrypted_path.get_directory_name());
			decrypted.ensure_branches_exist();

			f.decrypt(decrypted, key);
		}
	}
	else if (control_path.is_file()) {

		auto parent = control_path.get_parent_branch();

		qpl::filesys::path decrypted_path = qpl::to_string(parent, control_path.get_file_name(), ".decrypted.", control_path.get_extension());

		auto name = control_path.get_file_name();
		auto split = qpl::split_string(control_path.get_file_name(), '.');

		if (split.size() && split.back() == "encrypted") {
			split.pop_back();
			name = qpl::to_string_format("a.b", split);
		}
		name += ".decrypted";

		qpl::size ctr = 0u;
		while (decrypted_path.exists()) {
			decrypted_path = qpl::to_string(parent, name, ctr, ".", control_path.get_extension());
			++ctr;
		}

		control_path.decrypt(decrypted_path, key);
	}
}

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


int main(int argc, char** argv) try {

	if (argc <= 1u) {
		qpl::println("drag a folder or file/s on this executable.");
		qpl::system_pause();
		return 0;
	}
	else {

		std::string encryption_way;
		bool use_encryption = true;

		while (true) {
			qpl::print("encrypt or decrypt\ne/d > ");
			encryption_way = qpl::get_input();
			if (qpl::string_equals_ignore_case(encryption_way, "e")) {
				use_encryption = true;
				break;
			}
			else if (qpl::string_equals_ignore_case(encryption_way, "d")) {
				use_encryption = false;
				break;
			}
		}

		qpl::clear_console();
		qpl::print("input encryption key > ");
		auto key = qpl::get_hidden_input();

		if (use_encryption) {
			qpl::print("encrypting . . . ");
		}
		else {
			qpl::print("decrypting . . . ");
		}

		qpl::clock clock;
		for (int i = 1; i < argc; ++i) {
			if (use_encryption) {
				encrypt(argv[i], key);
			}
			else {
				decrypt(argv[i], key);
			}
		}
		qpl::println("done. took ", clock.elapsed_str());
		qpl::system_pause();
	}


}
catch (std::exception& any) {
	qpl::println("caught exception:\n", any.what());
	qpl::system_pause();
}