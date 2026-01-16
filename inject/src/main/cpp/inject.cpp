// inject.cpp - SpoofXManager v7.2.0 - GPS DEX Injection Support
// [RULE 1-5 COMPLIANT]
#include <android/log.h>
#include <sys/system_properties.h>
#include <jni.h>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <string_view>
#include <cstdlib>
#include <cerrno>
#include <poll.h>
#include "dobby.h"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SpoofX-Inject", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SpoofX-Inject", __VA_ARGS__)

#define FILE_IO_TIMEOUT_MS 200

// [PROTOCOL] Must match zygisk.cpp definition exactly
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

// [RULE 3] Robust I/O Wrapper with Timeout
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

// [RULE 2] Static State & Atomic Callback
class SpoofState {
public:
    static DeviceProfile profile;
    static std::atomic<bool> isActive;
};
DeviceProfile SpoofState::profile = {};
std::atomic<bool> SpoofState::isActive{false};

// [RULE 2] Atomic callback pointers - Thread Safety
using T_Callback = void (*)(void *, const char *, const char *, uint32_t);
using T_SysPropRead = void (*)(prop_info *, T_Callback, void *);

static std::atomic<T_Callback> o_callback{nullptr};
static std::atomic<T_SysPropRead> o_system_property_read_callback{nullptr};

// Validation Logic
static bool validateAppDirectory(const std::string& appDir) {
    if (appDir.find("/data/") != 0) return false;
    if (appDir.length() > 256) return false;
    if (appDir.find("/data/system") == 0 || appDir.find("/data/app/") == 0) return false;
    return true;
}

static bool validateFingerprint(const DeviceProfile& profile) {
    std::string_view fp(profile.FINGERPRINT);
    if (fp.length() < 10 || fp.length() > 255) return false;
    
    int slashes = 0, colons = 0;
    for (char c : fp) {
        if (c == '/') slashes++;
        else if (c == ':') colons++;
    }
    return (slashes >= 5 && colons >= 2);
}

// [RULE 4] my_ prefix for hook replacement
static void my_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    T_Callback original = o_callback.load(std::memory_order_relaxed);
    if (!original || !cookie || !name || !value) return;
    
    std::string_view prop(name);
    const char* spoofedVal = value;

    if (SpoofState::isActive.load(std::memory_order_relaxed)) {
        if (prop == "init.svc.adbd") spoofedVal = "stopped";
        else if (prop == "sys.usb.state") spoofedVal = "mtp";
        else if (prop.ends_with(".manufacturer")) spoofedVal = SpoofState::profile.MANUFACTURER;
        else if (prop.ends_with(".model")) spoofedVal = SpoofState::profile.MODEL;
        else if (prop.ends_with(".fingerprint")) spoofedVal = SpoofState::profile.FINGERPRINT;
        else if (prop.ends_with(".brand")) spoofedVal = SpoofState::profile.BRAND;
        else if (prop.ends_with(".product")) spoofedVal = SpoofState::profile.PRODUCT;
        else if (prop.ends_with(".device")) spoofedVal = SpoofState::profile.DEVICE;
        else if (prop.ends_with(".release")) spoofedVal = SpoofState::profile.RELEASE;
        else if (prop.ends_with(".build.id")) spoofedVal = SpoofState::profile.ID;
        else if (prop.ends_with(".incremental")) spoofedVal = SpoofState::profile.INCREMENTAL;
        else if (prop.ends_with(".type")) spoofedVal = SpoofState::profile.TYPE;
        else if (prop.ends_with(".tags")) spoofedVal = SpoofState::profile.TAGS;
    }

    if (SpoofState::profile.debugMode && strcmp(value, spoofedVal) != 0) {
        LOGD("[%s] %s -> %s", SpoofState::profile.profileName, name, spoofedVal);
    }

    original(cookie, name, spoofedVal, serial);
}

// [RULE 4] my_ prefix for hook replacement
static void my_system_property_read_callback(prop_info *pi, T_Callback callback, void *cookie) {
    if (pi && callback && cookie) {
        o_callback.store(callback, std::memory_order_relaxed);
    }
    
    auto orig = o_system_property_read_callback.load(std::memory_order_relaxed);
    if (orig) {
        orig(pi, my_callback, cookie);
    }
}

// [RULE 3] JNI Helper with Push/Pop LocalFrame for memory safety
class JNIHelper {
    JNIEnv* env;
public:
    explicit JNIHelper(JNIEnv* e) : env(e) {}
    
    bool setField(const char* clsName, const char* field, const char* val) {
        if (!val || strlen(val) == 0) return true;
        
        if (env->PushLocalFrame(16) < 0) return false;

        bool result = true;
        do {
            jclass cls = env->FindClass(clsName);
            if (env->ExceptionCheck()) { env->ExceptionClear(); result = false; break; }
            
            jfieldID fid = env->GetStaticFieldID(cls, field, "Ljava/lang/String;");
            if (env->ExceptionCheck()) { env->ExceptionClear(); result = false; break; }
            
            jstring jStr = env->NewStringUTF(val);
            if (env->ExceptionCheck()) { env->ExceptionClear(); result = false; break; }
            
            env->SetStaticObjectField(cls, fid, jStr);
            if (env->ExceptionCheck()) { env->ExceptionClear(); }
        } while (false);

        env->PopLocalFrame(nullptr);
        return result;
    }
};

// ============================================================================
// GPS DEX INJECTION - Following PlayIntegrityFix Pattern
// ============================================================================

/**
 * [RULE 3] Inject GPS DEX and call GpsSpoofingEngine.initialize()
 * Uses PathClassLoader following PlayIntegrityFix architecture
 * 
 * @param env JNI Environment
 * @param appDir Application data directory containing gps_classes.dex
 * @param lat Target latitude
 * @param lon Target longitude  
 * @param accuracy GPS accuracy in meters
 * @return true if injection successful
 */
static bool injectGpsDex(JNIEnv* env, const std::string& appDir, 
                          double lat, double lon, float accuracy) {
    
    // [RULE 3] Use PushLocalFrame to prevent JNI reference leak
    if (env->PushLocalFrame(32) < 0) {
        LOGE("GPS: PushLocalFrame failed");
        return false;
    }
    
    bool success = false;
    
    do {
        // Step 1: Get system ClassLoader
        jclass clClass = env->FindClass("java/lang/ClassLoader");
        if (env->ExceptionCheck()) { 
            env->ExceptionDescribe();
            env->ExceptionClear(); 
            LOGE("GPS: ClassLoader class not found");
            break; 
        }
        
        jmethodID getSystemClassLoader = env->GetStaticMethodID(
            clClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            LOGE("GPS: getSystemClassLoader not found");
            break; 
        }
        
        jobject systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);
        if (env->ExceptionCheck()) { 
            env->ExceptionDescribe();
            env->ExceptionClear(); 
            LOGE("GPS: getSystemClassLoader call failed");
            break; 
        }
        
        // Step 2: Create PathClassLoader for GPS DEX
        jclass dexClClass = env->FindClass("dalvik/system/PathClassLoader");
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            LOGE("GPS: PathClassLoader class not found");
            break; 
        }
        
        jmethodID dexClInit = env->GetMethodID(
            dexClClass, "<init>", "(Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            LOGE("GPS: PathClassLoader constructor not found");
            break; 
        }
        
        std::string dexPath = appDir + "/gps_classes.dex";
        jstring jDexPath = env->NewStringUTF(dexPath.c_str());
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            break; 
        }
        
        jobject dexClassLoader = env->NewObject(dexClClass, dexClInit, jDexPath, systemClassLoader);
        if (env->ExceptionCheck()) { 
            env->ExceptionDescribe();
            env->ExceptionClear(); 
            LOGE("GPS: Failed to create PathClassLoader for %s", dexPath.c_str());
            break; 
        }
        
        LOGD("GPS: PathClassLoader created for %s", dexPath.c_str());
        
        // Step 3: Load GpsSpoofingEngine class
        jmethodID loadClass = env->GetMethodID(
            clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            LOGE("GPS: loadClass method not found");
            break; 
        }
        
        jstring className = env->NewStringUTF("es.thoitiet.spooxmanager.GpsSpoofingEngine");
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            break; 
        }
        
        jobject entryClassObj = env->CallObjectMethod(dexClassLoader, loadClass, className);
        if (env->ExceptionCheck()) { 
            env->ExceptionDescribe();
            env->ExceptionClear(); 
            LOGE("GPS: Failed to load GpsSpoofingEngine class");
            break; 
        }
        
        auto gpsEngineClass = static_cast<jclass>(entryClassObj);
        
        LOGD("GPS: GpsSpoofingEngine class loaded");
        
        // Step 4: Call static initialize(double, double, float)
        jmethodID initMethod = env->GetStaticMethodID(
            gpsEngineClass, "initialize", "(DDF)V");
        if (env->ExceptionCheck()) { 
            env->ExceptionClear(); 
            LOGE("GPS: initialize method not found");
            break; 
        }
        
        env->CallStaticVoidMethod(gpsEngineClass, initMethod, 
                                   static_cast<jdouble>(lat), 
                                   static_cast<jdouble>(lon), 
                                   static_cast<jfloat>(accuracy));
        if (env->ExceptionCheck()) { 
            env->ExceptionDescribe();
            env->ExceptionClear(); 
            LOGE("GPS: initialize call failed");
            break; 
        }
        
        LOGD("GPS: GpsSpoofingEngine.initialize(%.6f, %.6f, %.1f) called successfully", 
             lat, lon, accuracy);
        success = true;
        
    } while (false);
    
    // [RULE 3] Always pop frame to clean up local references
    env->PopLocalFrame(nullptr);
    
    return success;
}

// ============================================================================
// MAIN INIT FUNCTION
// ============================================================================

extern "C" [[gnu::visibility("default")]] bool init(JNIEnv* env, const std::string& appDir) {
    if (!validateAppDirectory(appDir)) {
        LOGE("INIT FAILED: Invalid App Directory: %s", appDir.c_str());
        return false;
    }

    // Load Profile
    std::string path = appDir + "/device_profile.bin";
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOGE("INIT FAILED: Cannot open profile at %s", path.c_str());
        return false;
    }

    // [RULE 3] Use robust timeout read
    if (xread_timeout(fd, &SpoofState::profile, sizeof(DeviceProfile), FILE_IO_TIMEOUT_MS) 
            != sizeof(DeviceProfile)) {
        LOGE("INIT FAILED: Profile read size mismatch or timeout");
        close(fd);
        return false;
    }
    close(fd);

    if (!validateFingerprint(SpoofState::profile)) {
        LOGE("INIT FAILED: Invalid Fingerprint structure: %s", SpoofState::profile.FINGERPRINT);
        return false;
    }

    // [RULE 2] Use atomic store
    SpoofState::isActive.store(true, std::memory_order_relaxed);
    
    // Safety: Dummy callback init
    static T_Callback dummy = [](void*, const char*, const char*, uint32_t){};
    o_callback.store(dummy, std::memory_order_relaxed);

    // Install Property Hook
    void *sym = DobbySymbolResolver(nullptr, "__system_property_read_callback");
    if (sym) {
        void* trampoline_stub = nullptr;
        int ret = DobbyHook(sym, (void *)my_system_property_read_callback, &trampoline_stub);
        if (ret == 0) {
            o_system_property_read_callback.store(
                reinterpret_cast<T_SysPropRead>(trampoline_stub), 
                std::memory_order_relaxed);
            LOGD("Property hook installed successfully");
        } else {
            LOGE("DobbyHook failed with code: %d", ret);
        }
    } else {
        LOGE("FATAL: Could not resolve __system_property_read_callback");
    }

    // JNI Build Field Updates
    JNIHelper jni(env);
    jni.setField("android/os/Build", "MANUFACTURER", SpoofState::profile.MANUFACTURER);
    jni.setField("android/os/Build", "MODEL", SpoofState::profile.MODEL);
    jni.setField("android/os/Build", "FINGERPRINT", SpoofState::profile.FINGERPRINT);
    jni.setField("android/os/Build", "BRAND", SpoofState::profile.BRAND);
    jni.setField("android/os/Build", "PRODUCT", SpoofState::profile.PRODUCT);
    jni.setField("android/os/Build", "DEVICE", SpoofState::profile.DEVICE);
    jni.setField("android/os/Build", "ID", SpoofState::profile.ID);
    jni.setField("android/os/Build", "TYPE", SpoofState::profile.TYPE);
    jni.setField("android/os/Build", "TAGS", SpoofState::profile.TAGS);
    jni.setField("android/os/Build$VERSION", "RELEASE", SpoofState::profile.RELEASE);
    jni.setField("android/os/Build$VERSION", "INCREMENTAL", SpoofState::profile.INCREMENTAL);

    // GPS DEX Injection (if enabled)
    if (SpoofState::profile.gpsEnabled) {
        LOGD("GPS spoofing enabled, injecting DEX...");
        bool gpsOk = injectGpsDex(env, appDir, 
                                   SpoofState::profile.gpsLatitude,
                                   SpoofState::profile.gpsLongitude,
                                   SpoofState::profile.gpsAccuracy);
        if (!gpsOk) {
            LOGE("GPS DEX injection failed, continuing without GPS spoofing");
        }
    }

    LOGD("SpoofX-Inject Initialized Successfully for profile: %s", SpoofState::profile.profileName);
    return true;
}
