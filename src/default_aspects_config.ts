type ParamLogConfig = {
    location: number;
    method: string;
}
type AspectConfig = {
    class: string;
    method: string;
    params?: string[];
    params_log?: ParamLogConfig[];
    handler?: any;
};
const gAspects: AspectConfig[] = [
    // ClipboardManager
    {
        class: "android.content.ClipboardManager",
        method: "getPrimaryClip",
        params: [],
    },
    {
        class: "android.content.ClipboardManager",
        method: "getPrimaryClipDescription",
        params: [],
    },
    {
        class: "android.content.ClipboardManager",
        method: "getText",
        params: [],
    },
    {
        class: "android.text.ClipboardManager",
        method: "getText",
        params: [],
    },
    // PackageInstaller
    {
        class: "android.app.ApplicationPackageManager",
        method: "getInstalledApplications",
        params: ["int"],
    },
    {
        class: "android.app.ApplicationPackageManager",
        method: "getInstalledPackages",
        params: ["int"],
    },
    // LocationManager
    {
        class: "android.location.LocationManager",
        method: "getLastKnownLocation",
    },
    {
        class: "android.location.LocationManager",
        method: "requestLocationUpdates",
    },
    {
        class: "android.location.LocationManager",
        method: "requestSingleUpdate",
    },
    {
        class: "android.location.LocationManager",
        method: "getCurrentLocation",
    },
    // AccountManager
    {
        class: "android.accounts.AccountManager",
        method: "getAccounts",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsByType",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsAndVisibilityForPackage",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsByTypeAndFeatures",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsByTypeForPackage",
    },
    // Cell location
    {
        class: "android.telephony.TelephonyManager",
        method: "getAllCellInfo",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getCellLocation",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getNeighboringCellInfo",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "listen",
    },
    // Wifi location
    {
        class: "android.net.wifi.WifiManager",
        method: "getScanResults",
    },
    {
        class: "android.net.wifi.WifiManager",
        method: "getConnectionInfo",
    },
    {
        class: "android.net.wifi.WifiManager",
        method: "getConfiguredNetworks",
    },
    // Device IDs
    {
        class: "android.telephony.TelephonyManager",
        method: "getDeviceId",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getImei",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getMeid",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getSimSerialNumber",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getSubscriberId",
    },
    // Audio
    {
        class: "android.media.AudioRecord",
        method: "startRecording",
    },
    // Camera
    {
        class: "android.hardware.camera2.CameraManager",
        method: "openCamera",
    },
    {
        class: "android.hardware.Camera",
        method: "open",
    },
    // Phone number
    {
        class: "android.telecom.TelecomManager",
        method: "getLine1Number",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getLine1Number",
    },
    // ContentResolver: Contact, Sms, Calendar, etc.
    {
        class: "android.content.ContentResolver",
        method: "query",
    },
    // Dex loaders
    {
        class: "dalvik.system.BaseDexClassLoader",
        method: "$init",
    },
    {
        class: "dalvik.system.DexClassLoader",
        method: "$init",
    },
    {
        class: "dalvik.system.PathClassLoader",
        method: "$init",
    },
    // So loaders
    {
        class: "java.lang.System",
        method: "load",
    },
    {
        class: "java.lang.Runtime",
        method: "load",
    },
    // Socket server
    {
        class: "java.net.ServerSocket",
        method: "$init",
    },
    // Network
    {
        class: "java.net.URL",
        method: "openConnection",
    },
    {
        class: "android.net.Network",
        method: "openConnection",
    },
    {
        class: "org.apache.http.client",
        method: "execute",
    },
    // Shell
    {
        class: "java.lang.Runtime",
        method: "exec",
    },
    // File
    {
        class: "android.content.Context",
        method: "openFileInput",
    },
    {
        class: "android.content.Context",
        method: "openOrCreateDatabase",
    },
    {
        class: "java.io.FileInputStream",
        method: "$init",
        params: [
            "java.lang.String"
        ],
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ]
    },
    {
        class: "java.io.FileInputStream",
        method: "$init",
        params: [
            "java.io.File"
        ],
        params_log: [
            {
                location: 0,
                method: "getCanonicalPath"
            },
        ]
    },
    {
        class: "java.io.FileOutputStream",
        method: "$init",
    },
    {
        class: "java.io.RandomAccessFile",
        method: "$init",
    }
];
export { AspectConfig };
export { gAspects };