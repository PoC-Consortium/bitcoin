// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
// GCC 14 MinGW filesystem status does not classify Windows reparse points.
// Preserve no-follow wallet scanning and reject file symlinks as wallet paths.
#ifndef BITCOIN_POCX_COMPAT_WINDOWS_WALLET_FS_H
#define BITCOIN_POCX_COMPAT_WINDOWS_WALLET_FS_H
#include <filesystem>
#include <system_error>
#if defined(_WIN32) && defined(__MINGW32__)
#include <windows.h>
#endif
namespace pocx::compat {
inline std::filesystem::file_status WalletEntryStatus(const std::filesystem::directory_entry& entry, bool follow = true)
{
#if defined(_WIN32) && defined(__MINGW32__)
    const DWORD attributes = GetFileAttributesW(entry.path().c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (!follow) return std::filesystem::file_status{std::filesystem::file_type::symlink};
        struct Handle {
            HANDLE value;
            ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        } handle{CreateFileW(entry.path().c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
        if (handle.value == INVALID_HANDLE_VALUE) {
            throw std::filesystem::filesystem_error{"Resolving wallet directory entry", entry.path(),
                std::error_code{static_cast<int>(GetLastError()), std::system_category()}};
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle.value, &info)) {
            throw std::filesystem::filesystem_error{"Reading wallet directory entry", entry.path(),
                std::error_code{static_cast<int>(GetLastError()), std::system_category()}};
        }
        return std::filesystem::file_status{(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            ? std::filesystem::file_type::directory : std::filesystem::file_type::regular};
    }
#endif
    return follow ? entry.status() : entry.symlink_status();
}
inline void PreserveWalletNoFollow(std::filesystem::recursive_directory_iterator& iterator)
{
#if defined(_WIN32) && defined(__MINGW32__)
    if (std::filesystem::is_symlink(WalletEntryStatus(*iterator, false))) iterator.disable_recursion_pending();
#else
    (void)iterator;
#endif
}
inline std::filesystem::file_status WalletPathSymlinkStatus(const std::filesystem::path& path) {
#if defined(_WIN32) && defined(__MINGW32__)
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return std::filesystem::file_status{std::filesystem::file_type::symlink};
#endif
    return std::filesystem::symlink_status(path);
}
}
#endif
