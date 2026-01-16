package es.thoitiet.spooxmanager;

import android.app.Application;
import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * SpoofX GPS Engine - Deep Field Replacement Strategy
 * Target: LocationManager.mService (ILocationManager Interface)
 * 
 * This class is loaded via PathClassLoader from native inject.cpp
 * and called via JNI to initialize GPS spoofing.
 */
public final class EntryPoint {
    private static final String TAG = "SpoofX-GPS";
    
    // Thread-safe coordinates storage
    private static volatile double TARGET_LAT = 0.0;
    private static volatile double TARGET_LON = 0.0;
    private static volatile float TARGET_ACCURACY = 5.0f;
    
    // Prevent double initialization
    private static volatile boolean isInitialized = false;

    /**
     * Entry point called via JNI from inject.cpp
     * Signature: (DDF)V
     */
    public static void initialize(double lat, double lon, float accuracy) {
        if (isInitialized) {
            Log.w(TAG, "Already initialized, skipping");
            return;
        }
        
        TARGET_LAT = lat;
        TARGET_LON = lon;
        TARGET_ACCURACY = accuracy;

        Log.i(TAG, String.format("Initializing GPS Engine: %.6f, %.6f (Acc: %.1f)", lat, lon, accuracy));

        // 1. Bypass Hidden API Restrictions (Android 9+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                HiddenApiBypass.addHiddenApiExemptions("");
                Log.d(TAG, "Hidden API bypass applied");
            } catch (Throwable t) {
                Log.e(TAG, "Hidden API bypass failed", t);
            }
        }

        // 2. Hook Application to get LocationManager instance
        try {
            hookLocationManager();
            isInitialized = true;
            Log.i(TAG, "GPS Engine initialized successfully");
        } catch (Throwable e) {
            Log.e(TAG, "Fatal: Failed to hook LocationManager", e);
        }
    }

    private static void hookLocationManager() throws Exception {
        // Step A: Get Application Instance via ActivityThread
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Method currentActivityThreadMethod = activityThreadClass.getDeclaredMethod("currentActivityThread");
        currentActivityThreadMethod.setAccessible(true);
        Object activityThread = currentActivityThreadMethod.invoke(null);

        if (activityThread == null) {
            Log.w(TAG, "ActivityThread is null, maybe too early?");
            return;
        }

        // Try getApplication()
        Application app = null;
        try {
            Method getApplicationMethod = activityThreadClass.getDeclaredMethod("getApplication");
            getApplicationMethod.setAccessible(true);
            app = (Application) getApplicationMethod.invoke(activityThread);
        } catch (NoSuchMethodException e) {
            Log.d(TAG, "getApplication() not found, trying mInitialApplication");
        }

        if (app == null) {
            // Fallback to mInitialApplication
            try {
                Field mInitialAppField = activityThreadClass.getDeclaredField("mInitialApplication");
                mInitialAppField.setAccessible(true);
                app = (Application) mInitialAppField.get(activityThread);
            } catch (NoSuchFieldException e) {
                Log.e(TAG, "mInitialApplication field not found");
            }
        }

        if (app == null) {
            Log.e(TAG, "Failed to retrieve Application instance");
            return;
        }

        // Step B: Get the LocationManager instance from the App Context
        LocationManager locationManager = (LocationManager) app.getSystemService(Context.LOCATION_SERVICE);
        
        if (locationManager == null) {
            Log.e(TAG, "LocationManager is null");
            return;
        }

        // Step C: Perform Deep Field Replacement on 'mService'
        replaceLocationManagerService(locationManager);
    }

    private static void replaceLocationManagerService(LocationManager manager) throws Exception {
        // 1. Find 'mService' field in LocationManager class hierarchy
        Field mServiceField = findFieldRecursive(LocationManager.class, "mService");
        if (mServiceField == null) {
            Log.e(TAG, "Cannot find 'mService' field in LocationManager");
            return;
        }
        
        mServiceField.setAccessible(true);
        
        // 2. Get the original ILocationManager binder (Stub.Proxy)
        Object originalService = mServiceField.get(manager);
        if (originalService == null) {
            Log.w(TAG, "Original mService is null, cannot wrap");
            return;
        }

        // 3. Create Dynamic Proxy for ILocationManager
        Class<?> iLocationManagerClass = Class.forName("android.location.ILocationManager");
        
        Object proxyService = Proxy.newProxyInstance(
                manager.getClass().getClassLoader(),
                new Class[]{iLocationManagerClass},
                new ILocationManagerProxyHandler(originalService)
        );

        // 4. Swap the field!
        mServiceField.set(manager, proxyService);
        Log.i(TAG, "Successfully replaced LocationManager.mService with Proxy");
    }

    /**
     * Handler for ILocationManager methods
     * Intercepts location-related calls and returns spoofed data
     */
    private static class ILocationManagerProxyHandler implements InvocationHandler {
        private final Object original; // The real system service binder proxy

        public ILocationManagerProxyHandler(Object original) {
            this.original = original;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String name = method.getName();

            // === SPOOFING LOGIC ===
            
            // 1. Block real location requests (cached & fresh)
            if ("getLastLocation".equals(name) || "getLastKnownLocation".equals(name)) {
                Log.d(TAG, "Intercepted " + name + ", returning fake location");
                return createFakeLocation();
            }
            
            // 2. Spoof Provider Status
            if ("isProviderEnabled".equals(name) || "isProviderEnabledForUser".equals(name)) {
                if (args != null && args.length > 0) {
                    String provider = (String) args[0];
                    if (LocationManager.GPS_PROVIDER.equals(provider) || 
                        LocationManager.NETWORK_PROVIDER.equals(provider)) {
                        Log.d(TAG, "Intercepted " + name + "(" + provider + "), returning true");
                        return true;
                    }
                }
            }

            // 3. Pass through all other methods to original
            try {
                return method.invoke(original, args);
            } catch (Throwable t) {
                // Handle InvocationTargetException
                Throwable cause = t.getCause();
                throw cause != null ? cause : t;
            }
        }

        private Location createFakeLocation() {
            Location loc = new Location(LocationManager.GPS_PROVIDER);
            loc.setLatitude(TARGET_LAT);
            loc.setLongitude(TARGET_LON);
            loc.setAccuracy(TARGET_ACCURACY);
            loc.setTime(System.currentTimeMillis());
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                loc.setElapsedRealtimeNanos(SystemClock.elapsedRealtimeNanos());
            }
            
            // Anti-cheat measures - realistic values
            loc.setAltitude(10.0);
            loc.setBearing(0.0f);
            loc.setSpeed(0.0f);
            
            // Mock extras (Satellites count is important for some checks)
            Bundle extras = new Bundle();
            extras.putInt("satellites", 12);
            loc.setExtras(extras);
            
            return loc;
        }
    }

    /**
     * Utility: Find field recursively up the class hierarchy
     */
    private static Field findFieldRecursive(Class<?> clazz, String fieldName) {
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            try {
                return current.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        return null;
    }
}
