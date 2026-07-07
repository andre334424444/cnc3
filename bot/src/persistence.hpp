// persistence.hpp — cross-platform persistence mechanisms.
//
// Ensures the bot survives reboots and runs on startup.
// Methods vary by platform:
//   Windows:  HKCU\...\Run registry key
//   Linux:    crontab @reboot entry

#pragma once

namespace persistence {

// Install persistence. Call once on first execution.
// Returns true if successfully installed (or already installed).
bool install();

// Remove persistence. Useful for uninstall/cleanup.
bool remove();

// Check if we're already persistent.
bool is_installed();

} // namespace persistence
