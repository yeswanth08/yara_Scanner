#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <map>
#include <yara.h>

// Define your YARA rules here
const char* YaraScanner::yara_rules = R"(
    rule ExampleRule {
        strings:
            $magic_string = "example"
        condition:
            $magic_string
    }
)";


class Logger {
public:
    static void log_debug(const std::string& message, const std::string& module_name) {
        std::cout << "[DEBUG][" << module_name << "] " << message << std::endl;
    }

    static void log_info(const std::string& message, const std::string& module_name) {
        std::cout << "[INFO][" << module_name << "] " << message << std::endl;
    }

    static void log_error(const std::string& message, const std::string& module_name) {
        std::cerr << "[ERROR][" << module_name << "] " << message << std::endl;
    }

    static void log_incident(const std::string& file_path, const std::string& matches, const std::string& rule_path) {
        std::cout << "[INCIDENT] Match found in file: " << file_path << " using rule: " << rule_path
                  << " Matches: " << matches << std::endl;
    }
};

class CommonFunctions {
public:
    static std::vector<std::string> read_file_lines(const std::string& file_path) {
        std::vector<std::string> lines_list;
        std::ifstream file(file_path);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                lines_list.push_back(line);
            }
            file.close();
        } else {
            Logger::log_error("Failed to open file", "CommonFunctions::read_file_lines");
        }
        return lines_list;
    }
     static std::vector<std::string> list_directory_files(const std::string& dir_path) {
        std::vector<std::string> file_list;

        try {
            for (const auto& entry : fs::directory_iterator(dir_path)) {
                if (entry.is_regular_file()) { 
                    file_list.push_back(entry.path().string()); 
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error listing directory files: " << e.what() << std::endl;
        }

        return file_list;
    }
};

class YaraScanner {
private:
    static const char* yara_rules = R"(
    rule ExampleRule {
        strings:
            $magic_string = "example"
        condition:
            $magic_string
    }
)";


public:
    static std::vector<std::map<std::string, std::string>> scan_file(const std::string& file_path) {
        std::vector<std::map<std::string, std::string>> match_list;

        static void initialize_yara() {
            yr_initialize();
        }

        // Load compiled YARA rules
         static YR_RULES* load_yara_rules() {
            YR_RULES* rules = nullptr;
            int result = yr_rules_load(compiled_rules_path, &rules);
            if (result != ERROR_SUCCESS) {
                return nullptr;
            }
            return rules;
        }
        int result = yr_rules_load_string(yara_rules, nullptr, &rules);
        if (result == ERROR_SUCCESS) {
            FILE* file = fopen(file_path.c_str(), "rb");
            if (file != nullptr) {
    
                YR_SCANNER* scanner = nullptr;
                yr_scanner_create(rules, &scanner);

                
                YR_SCAN_CONTEXT* context = nullptr;
                yr_scan_file(file, scanner, nullptr, nullptr, 0, &context);

                
                const uint8_t* match_data;
                int scan_result;
                while (yr_scan_get_next_match(scanner, context, &match_data, &scan_result) == ERROR_SUCCESS) {
                    
                    std::map<std::string, std::string> match;
                    match["rule_name"] = yr_rule_identifier(scan_result);
                    match["rule_name"] = yr_rule_identifier(scan_result);
                    match["match_offset"] = std::to_string(yr_rule_offset(scan_result));
                    match["match_length"] = std::to_string(yr_rule_length(scan_result));
                    // Add more match information as needed
                    match_list.push_back(match);

                    Logger::log_incident(file_path, "Match found", "YARA rule name");
                }

                yr_scan_context_destroy(context);
                yr_scanner_destroy(scanner);
                fclose(file);
            }
            yr_rules_destroy(rules);
        }

        yr_finalize();

        return match_list;
    }

  static std::vector<std::map<std::string, std::string>> scan_directory(const std::string& dir_path) {
    std::vector<std::map<std::string, std::string>> match_list;

    std::vector<std::string> file_list = CommonFunctions::list_directory_files(dir_path);
    for (const auto& file : file_list) {
        // Perform YARA scan for each file in the directory
        std::vector<std::map<std::string, std::string>> matches = scan_file(file);
        match_list.insert(match_list.end(), matches.begin(), matches.end());
    }

    return match_list;
}

};

int main() {
    std::string file_to_scan = "path/to/file.ext";
    std::vector<std::map<std::string, std::string>> file_matches = YaraScanner::scan_file(file_to_scan);

    std::string directory_to_scan = "path/to/directory";
    std::vector<std::map<std::string, std::string>> dir_matches = YaraScanner::scan_directory(directory_to_scan);

    // Handle and display matches for the file
    if (!file_matches.empty()) {
        std::cout << "Matches found in file:" << std::endl;
        for (const auto& match : file_matches) {
            for (const auto& pair : match) {
                std::cout << pair.first << ": " << pair.second << std::endl;
            }
        }
    } else {
        std::cout << "No matches found in file." << std::endl;
    }

    // Handle and display matches for the directory
    if (!dir_matches.empty()) {
        std::cout << "Matches found in directory:" << std::endl;
        for (const auto& match : dir_matches) {
            for (const auto& pair : match) {
                std::cout << pair.first << ": " << pair.second << std::endl;
            }
        }
    } else {
        std::cout << "No matches found in directory." << std::endl;
    }

    return 0;
}
