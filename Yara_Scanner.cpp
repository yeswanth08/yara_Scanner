#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <map>

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
};

class YaraScanner {
public:
    static std::vector<std::map<std::string, std::string>> scan_file(const std::string& file_path) {
        std::vector<std::map<std::string, std::string>> match_list;
        std::vector<std::string> lines = CommonFunctions::read_file_lines(file_path);
        // Implementation for scanning a single file and matching with YARA rules
        return match_list;
    }

    static std::vector<std::map<std::string, std::string>> scan_access_logs(const std::string& access_logs_file_path, const std::string& www_dir_path, int tail = 0) {
        std::vector<std::map<std::string, std::string>> match_list;
        std::vector<std::string> lines = CommonFunctions::read_file_lines(access_logs_file_path);
        // Implementation for scanning access logs and matching with YARA rules
        return match_list;
    }
};

int main() {
    std::string access_logs_file_path = "C:\\Users\\HP\\Onedrive\\yara_Scanner\\access_logs.txt";
    std::string www_dir_path = "C:\\Users\\HP\\Onedrive\\yara_Scanner";
    std::vector<std::map<std::string, std::string>> matches = YaraScanner::scan_access_logs(access_logs_file_path, www_dir_path, 10);
    return 0;
}
