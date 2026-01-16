// zygisk.cpp - SpoofXManager v7.2.0 - GPS DEX Injection Support
// [RULE 1-5 COMPLIANT]
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <dlfcn.h>
#include <poll.h>
#include <string>
#include <vector>
#include <cstring>
#include <climits>
#include "zygisk.hpp"
#include "json.hpp"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SpoofX-Zygisk", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SpoofX-Zygisk", __VA_ARGS__)

#define MODULE_DIR "/data/adb/modules/SpoofXManager"
#define CONFIG_PATH MODULE_DIR "/config.json"
#define INJECT_LIB_64 MODULE_DIR "/inject/arm64-v8a.so"
#define INJECT_LIB_32 MODULE_DIR "/inject/armeabi-v7a.so"
#define GPS_DEX_PATH MODULE_DIR "/gps_classes.dex"

// [SECURITY LIMITS]
#define IPC_TIMEOUT_MS 1000
#define MAX_CONFIG_SIZE (100 * 1024)      // 100KB Limit
#define MAX_LIB_SIZE (10 * 1024 * 1024)   // 10MB Limit
#define MAX_DEX_SIZE (5 * 1024 * 1024)    // 5MB Limit

// [PROTOCOL] Must match inject.cpp DeviceProfile exactly
struct DeviceProfile {
    char profileName[64];
    char MANUFACTURER[64];
    char MODEL[64];
    char FINGERPRINT[256];
    char BRAND[64];
    char PRODUCT[64];
    char DEVICE[64];
    char RELEASE[32];
    char ID[64];
    char INCREMENTAL[64];
    char TYPE[32];
    char TAGS[32];
    bool debugMode;
    // GPS Spoofing Fields
    double gpsLatitude;
    double gpsLongitude;
    float gpsAccuracy;
    bool gpsEnabled;
};

// [RULE 3] Robust I/O with Timeout - x prefix for utility functions
static ssize_t xread_timeout(int fd, void *buffer, size_t count, int timeout_ms) {
    char *buf = static_cast<char *>(buffer);
    size_t remaining = count;
    struct pollfd pfd = {fd, POLLIN, 0};
    while (remaining > 0) {
        if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
        ssize_t ret = TEMP_FAILURE_RETRY(read(fd, buf, remaining));
        if (ret <= 0) return -1;
        buf += ret;
        remaining -= ret;
    }
    return count - remaining;
}

static ssize_t xwrite_timeout(int fd, const void *buffer, size_t count, int timeout_ms) {
    const char *buf = static_cast<const char *>(buffer);
    size_t remaining = count;
    struct pollfd pfd = {fd, POLLOUT, 0};
    while (remaining > 0) {
        if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
        ssize_t ret = TEMP_FAILURE_RETRY(write(fd, buf, remaining));
        if (ret < 0) return -1;
        buf += ret;
        remaining -= ret;
    }
    return count - remaining;
}

// [OPTIMIZATION] Zero-Allocation Fingerprint Parser (Stack Based)
static void parseFingerprintToProfile(DeviceProfile& profile) {
    const char* fp = profile.FINGERPRINT;
    size_t len = strlen(fp);
    if (len == 0) return;

    const char* segments[8] = {nullptr};
    size_t segLens[8] = {0};
    int segCount = 0;
    
    const char* start = fp;
    for (size_t i = 0; i <= len && segCount < 8; ++i) {
        if (i == len || fp[i] == '/' || fp[i] == ':') {
            if (i > static_cast<size_t>(start - fp)) {
                segments[segCount] = start;
                segLens[segCount] = i - (start - fp);
                segCount++;
            }
            start = fp + i + 1;
        }
    }
    
    auto safeCopy = [](char* dest, const char* src, size_t srcLen, size_t destSize) {
        size_t copyLen = (srcLen < destSize - 1) ? srcLen : destSize - 1;
        memcpy(dest, src, copyLen);
        dest[copyLen] = '\0';
    };

    if (segCount >= 8) {
        safeCopy(profile.BRAND, segments[0], segLens[0], sizeof(profile.BRAND));
        safeCopy(profile.PRODUCT, segments[1], segLens[1], sizeof(profile.PRODUCT));
        safeCopy(profile.DEVICE, segments[2], segLens[2], sizeof(profile.DEVICE));
        safeCopy(profile.RELEASE, segments[3], segLens[3], sizeof(profile.RELEASE));
        safeCopy(profile.ID, segments[4], segLens[4], sizeof(profile.ID));
        safeCopy(profile.INCREMENTAL, segments[5], segLens[5], sizeof(profile.INCREMENTAL));
        safeCopy(profile.TYPE, segments[6], segLens[6], sizeof(profile.TYPE));
        safeCopy(profile.TAGS, segments[7], segLens[7], sizeof(profile.TAGS));
    }
}

// [SECURITY] Atomic Write + Chown + Symlink Protection
static bool atomicWriteWithOwnership(const std::string& path, const void* data, size_t len, uid_t uid, gid_t gid) {
    std::string tmpPath = path + ".tmp";
    int fd = open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;

    flock(fd, LOCK_EX);
    if (fchown(fd, uid, gid) != 0) { close(fd); unlink(tmpPath.c_str()); return false; }

    if (xwrite_timeout(fd, data, len, IPC_TIMEOUT_MS) != static_cast<ssize_t>(len)) {
        close(fd); unlink(tmpPath.c_str()); return false;
    }

    fsync(fd);
    flock(fd, LOCK_UN);
    close(fd);

    if (rename(tmpPath.c_str(), path.c_str()) != 0) { unlink(tmpPath.c_str()); return false; }
    return true;
}

// [SECURITY] Chunked Copy (Prevent OOM) - [RULE 3] 64KB Stack Buffer
static bool copyFileWithOwnership(const std::string& src, const std::string& dst, 
                                   uid_t uid, gid_t gid, off_t maxSize = MAX_LIB_SIZE) {
    int srcFd = open(src.c_str(), O_RDONLY);
    if (srcFd < 0) return false;

    struct stat st;
    if (fstat(srcFd, &st) != 0 || st.st_size > maxSize) { close(srcFd); return false; }
    
    std::string tmpPath = dst + ".tmp";
    int dstFd = open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (dstFd < 0) { close(srcFd); return false; }
    
    if (fchown(dstFd, uid, gid) != 0) { 
        close(srcFd); close(dstFd); unlink(tmpPath.c_str()); return false; 
    }
    
    char buffer[65536]; // 64KB Stack Buffer - [RULE 3]
    ssize_t totalRead = 0;
    bool success = true;

    while (totalRead < st.st_size) {
        ssize_t toRead = (st.st_size - totalRead > 65536) ? 65536 : st.st_size - totalRead;
        ssize_t nRead = xread_timeout(srcFd, buffer, toRead, IPC_TIMEOUT_MS);
        if (nRead != toRead || xwrite_timeout(dstFd, buffer, nRead, IPC_TIMEOUT_MS) != nRead) {
            success = false; break;
        }
        totalRead += nRead;
    }
    
    close(srcFd);
    fsync(dstFd);
    close(dstFd);

    if (success && rename(tmpPath.c_str(), dst.c_str()) == 0) return true;
    unlink(tmpPath.c_str());
    return false;
}

// [RULE 5] Companion Logic - All file I/O happens here in root context
static void companion(int fd) {
    size_t pkgLen = 0, dirLen = 0;
    uid_t appUid; gid_t appGid;

    // Read package name
    if (xread_timeout(fd, &pkgLen, sizeof(size_t), IPC_TIMEOUT_MS) != sizeof(size_t) || pkgLen > 256) return;
    std::string packageName(pkgLen, '\0');
    if (xread_timeout(fd, packageName.data(), pkgLen, IPC_TIMEOUT_MS) != static_cast<ssize_t>(pkgLen)) return;

    // Read app directory
    if (xread_timeout(fd, &dirLen, sizeof(size_t), IPC_TIMEOUT_MS) != sizeof(size_t) || dirLen > 4096) return;
    std::string appDir(dirLen, '\0');
    if (xread_timeout(fd, appDir.data(), dirLen, IPC_TIMEOUT_MS) != static_cast<ssize_t>(dirLen)) return;

    // Read UID/GID for ownership transfer
    if (xread_timeout(fd, &appUid, sizeof(uid_t), IPC_TIMEOUT_MS) != sizeof(uid_t)) return;
    if (xread_timeout(fd, &appGid, sizeof(gid_t), IPC_TIMEOUT_MS) != sizeof(gid_t)) return;

    bool shouldSpoof = false;
    DeviceProfile profile = {};

    // [RULE 3] File I/O with proper resource management
    do {
        int configFd = open(CONFIG_PATH, O_RDONLY);
        if (configFd < 0) break;

        struct stat st;
        if (fstat(configFd, &st) != 0 || st.st_size <= 0 || st.st_size > MAX_CONFIG_SIZE) {
            close(configFd);
            break;
        }

        std::vector<char> buf(st.st_size);
        ssize_t bytesRead = xread_timeout(configFd, buf.data(), st.st_size, IPC_TIMEOUT_MS);
        close(configFd);  // [RULE 3] Always close immediately after read

        if (bytesRead != st.st_size) break;

        nlohmann::json json = nlohmann::json::parse(buf.begin(), buf.end(), nullptr, false);
        if (json.is_discarded() || !json.is_object()) break;

        // Search for matching package
        for (auto& [key, value] : json.items()) {
            if (!key.starts_with("PACKAGES_") || key.ends_with("_DEVICE") || !value.is_array()) continue;

            for (const auto& pkg : value) {
                if (pkg != packageName) continue;

                shouldSpoof = true;
                std::string deviceKey = key + "_DEVICE";
                if (json.contains(deviceKey)) {
                    const auto& dev = json[deviceKey];
                    strncpy(profile.profileName, key.substr(9).c_str(), 63);
                    if (dev.contains("MANUFACTURER")) strncpy(profile.MANUFACTURER, dev["MANUFACTURER"].get<std::string>().c_str(), 63);
                    if (dev.contains("MODEL")) strncpy(profile.MODEL, dev["MODEL"].get<std::string>().c_str(), 63);
                    if (dev.contains("FINGERPRINT")) strncpy(profile.FINGERPRINT, dev["FINGERPRINT"].get<std::string>().c_str(), 255);
                    profile.debugMode = dev.value("DEBUG", false);
                    
                    // Parse GPS config
                    if (dev.contains("GPS") && dev["GPS"].is_object()) {
                        const auto& gps = dev["GPS"];
                        profile.gpsEnabled = gps.value("enabled", false);
                        profile.gpsLatitude = gps.value("latitude", 0.0);
                        profile.gpsLongitude = gps.value("longitude", 0.0);
                        profile.gpsAccuracy = gps.value("accuracy", 5.0f);
                        LOGD("[COMPANION] GPS Config: enabled=%d, lat=%.6f, lon=%.6f, acc=%.1f",
                             profile.gpsEnabled, profile.gpsLatitude, profile.gpsLongitude, profile.gpsAccuracy);
                    }
                    
                    parseFingerprintToProfile(profile);
                }
                break;
            }
            if (shouldSpoof) break;
        }
    } while (false);

    // Send decision to module
    xwrite_timeout(fd, &shouldSpoof, sizeof(bool), IPC_TIMEOUT_MS);
    if (!shouldSpoof) return;

    // Copy files to app directory with proper ownership
    std::string libDest = appDir + "/libinject.so";
    std::string profDest = appDir + "/device_profile.bin";

#if defined(__aarch64__)
    bool ok = copyFileWithOwnership(INJECT_LIB_64, libDest, appUid, appGid);
#else
    bool ok = copyFileWithOwnership(INJECT_LIB_32, libDest, appUid, appGid);
#endif

    ok &= atomicWriteWithOwnership(profDest, &profile, sizeof(DeviceProfile), appUid, appGid);

    // Copy GPS DEX if GPS is enabled
    if (ok && profile.gpsEnabled) {
        std::string gpsDexDest = appDir + "/gps_classes.dex";
        if (access(GPS_DEX_PATH, F_OK) == 0) {
            ok &= copyFileWithOwnership(GPS_DEX_PATH, gpsDexDest, appUid, appGid, MAX_DEX_SIZE);
            if (ok) {
                LOGD("[COMPANION] GPS DEX copied to %s", gpsDexDest.c_str());
            } else {
                LOGE("[COMPANION] Failed to copy GPS DEX");
            }
        } else {
            LOGE("[COMPANION] GPS DEX not found at %s", GPS_DEX_PATH);
            ok = false;
        }
    }

    xwrite_timeout(fd, &ok, sizeof(bool), IPC_TIMEOUT_MS);
}

// [RULE 1] Zygisk Module Implementation
using namespace zygisk;

class SpoofXManager : public ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    // [RULE 1] Early Exit - All filtering in preAppSpecialize
    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args || !args->app_data_dir || !args->nice_name) {
            api->setOption(DLCLOSE_MODULE_LIBRARY); return;
        }

        // [RULE 3] JNI Exception Safety
        const char *rawDir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (env->ExceptionCheck() || !rawDir) {
            env->ExceptionClear();
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }
        std::string dir(rawDir);
        env->ReleaseStringUTFChars(args->app_data_dir, rawDir);

        const char *rawPkg = env->GetStringUTFChars(args->nice_name, nullptr);
        if (env->ExceptionCheck() || !rawPkg) {
            env->ExceptionClear();
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }
        std::string pkg(rawPkg);
        env->ReleaseStringUTFChars(args->nice_name, rawPkg);

        int fd = api->connectCompanion();
        if (fd < 0) { api->setOption(DLCLOSE_MODULE_LIBRARY); return; }

        size_t pkgLen = pkg.size(), dirLen = dir.size();
        uid_t uid = args->uid; gid_t gid = args->gid;

        // [RULE 3] Timeout-based IPC
        if (xwrite_timeout(fd, &pkgLen, sizeof(size_t), IPC_TIMEOUT_MS) < 0 ||
            xwrite_timeout(fd, pkg.data(), pkgLen, IPC_TIMEOUT_MS) < 0 ||
            xwrite_timeout(fd, &dirLen, sizeof(size_t), IPC_TIMEOUT_MS) < 0 ||
            xwrite_timeout(fd, dir.data(), dirLen, IPC_TIMEOUT_MS) < 0 ||
            xwrite_timeout(fd, &uid, sizeof(uid_t), IPC_TIMEOUT_MS) < 0 ||
            xwrite_timeout(fd, &gid, sizeof(gid_t), IPC_TIMEOUT_MS) < 0) {
            close(fd); api->setOption(DLCLOSE_MODULE_LIBRARY); return;
        }

        bool shouldSpoof = false;
        if (xread_timeout(fd, &shouldSpoof, sizeof(bool), IPC_TIMEOUT_MS) != sizeof(bool)) shouldSpoof = false;

        // [RULE 1] Early Exit if not target
        if (!shouldSpoof) {
            close(fd); api->setOption(DLCLOSE_MODULE_LIBRARY); return;
        }

        bool ready = false;
        if (xread_timeout(fd, &ready, sizeof(bool), IPC_TIMEOUT_MS) != sizeof(bool)) ready = false;
        close(fd);

        if (ready) {
            appDir = dir;
            api->setOption(FORCE_DENYLIST_UNMOUNT);
        } else {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (appDir.empty()) return;

        std::string libPath = appDir + "/libinject.so";
        void *handle = dlopen(libPath.c_str(), RTLD_NOW);
        if (!handle) { 
            LOGE("dlopen failed: %s", dlerror()); 
            return; 
        }

        // [RULE 4] Clear naming for init function
        auto initFn = reinterpret_cast<bool (*)(JNIEnv*, const std::string&)>(dlsym(handle, "init"));
        if (initFn) {
            initFn(env, appDir);
        } else {
            LOGE("dlsym 'init' failed");
        }
    }

    // [RULE 1] Always detach from system server
    void preServerSpecialize(ServerSpecializeArgs *args) override {
        api->setOption(DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::string appDir;
};

REGISTER_ZYGISK_MODULE(SpoofXManager)
REGISTER_ZYGISK_COMPANION(companion)