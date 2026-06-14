#include "LogAction.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace https_guard {

LogAction::LogAction(std::string output_path)
    : output_path_(std::move(output_path))
{
    const auto directory = std::filesystem::path(output_path_).parent_path();
    if (!directory.empty()) {
        std::filesystem::create_directories(directory);
    }
}

void LogAction::execute(const hg_event& event,
                        const std::string& message_id,
                        const std::string& message,
                        const std::string& severity)
{
    const std::string payload = formatter_.format(event, message_id, message, severity);
    write_event(payload);
    std::cout << "[HTTPS-Guard] " << message << "\n";
}

void LogAction::write_event(const std::string& line)
{
    std::ofstream ofs(output_path_, std::ios::app);
    if (!ofs) {
        std::cerr << "failed to open event log: " << output_path_ << "\n";
        return;
    }
    ofs << line << '\n';
}

}  // namespace https_guard
