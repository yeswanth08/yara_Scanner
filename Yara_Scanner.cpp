#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>


bool is_directory(const std::string& path) {
    DWORD attrib = GetFileAttributes(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Function to scan a file 
bool scan_file(const std::string& file_path, const std::string& pattern) {
    std::ifstream file(file_path);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find(pattern) != std::string::npos) {
                file.close();
                return true;  
            }
        }
        std::cout<<" File scanning of: "<<file_path<<std::endl;
        file.close();
    } else {
        std::cerr << "Error opening file: " << file_path << std::endl;
    }
    return false;  
}

// Function to scan files in a directory 
void scan_directory_recursive(const std::string& dir_path, const std::string& pattern) {
    WIN32_FIND_DATA find_data;
    HANDLE hFind = FindFirstFile((dir_path + "\\*").c_str(), &find_data);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string file_name = find_data.cFileName;
                std::string full_path = dir_path + "\\" + file_name;
                if (scan_file(full_path, pattern)) {
                    std::cout << "Pattern found in file: " << full_path << std::endl;
                }
            } else if (strcmp(find_data.cFileName, ".") != 0 && strcmp(find_data.cFileName, "..") != 0) {
                std::string sub_dir_path = dir_path + "\\" + find_data.cFileName;
                scan_directory_recursive(sub_dir_path, pattern);
            }
        } while (FindNextFile(hFind, &find_data) != 0);
        FindClose(hFind);
        std::cout << "Directory is scanned: "<<dir_path<<std::endl;
    } else {
        std::cerr << "Error opening directory: " << dir_path << std::endl;
    }
}

int main() {

    // pattern
    std::string pattern_to_scan = "malware";

    std::string directory_path = "D:/C_Programming/";
    std::string file_path = "D:/C_Programming/Array.c";

    if (!is_directory(directory_path)) {
        std::cerr << "Invalid directory path." << std::endl;
        return 1;
    }

    scan_directory_recursive(directory_path, pattern_to_scan);
    scan_file(file_path,pattern_to_scan);

    return 0;
}
