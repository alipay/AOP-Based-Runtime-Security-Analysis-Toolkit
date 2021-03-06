type ParamLogConfig = {
    location: number;
    method: string;
}
type AspectConfig = {
    class: string;
    method: string;
    params?: string[];
    params_log?: ParamLogConfig[];
//    handler?: any;
    category: string;
};

function is_valid_param_config(param: any) {
    if (! ("location" in param) || (typeof param.location) !== "number") {
        return false;
    }
    if (! ("method" in param) || (typeof param.method) !== "string") {
        return false;
    }
    return true;
}

function is_valid_config(configs: any) {
    if (! Array.isArray(configs)) {
        return false;
    }

    for (let config of configs) {
        if (! ("class" in config) || (typeof config.class) !== "string") {
            return false;
        }
        if (! ("method" in config) || (typeof config.method) !== "string") {
            return false;
        }
        if (! ("category" in config) || (typeof config.category) !== "string") {
            return false;
        }
        if ("params" in config) {
            if (! Array.isArray(config.params)) {
                return false;
            }
            for (let p of config.params) {
                if (typeof p !== "string") {
                    return false;
                }
            }
        }
        if ("params_log" in config) {
            if (! Array.isArray(config.params_log)) {
                return false;
            }
            for (let pl of config.params_log) {
                if (! is_valid_param_config(pl)) {
                    return false;
                }
            }
        }
    }
    return true;
}

const gAspects: AspectConfig[] = [
    // ClipboardManager
    {
        class: "android.content.ClipboardManager",
        method: "getPrimaryClip",
        params: [],
        category: "Privacy",
    },
    {
        class: "android.content.ClipboardManager",
        method: "getPrimaryClipDescription",
        params: [],
        category: "Privacy",
    },
    {
        class: "android.content.ClipboardManager",
        method: "getText",
        params: [],
        category: "Privacy",
    },
    {
        class: "android.text.ClipboardManager",
        method: "getText",
        params: [],
        category: "Privacy",
    },
    // PackageInstaller
    {
        class: "android.app.ApplicationPackageManager",
        method: "getInstalledApplications",
        params: ["int"],
        category: "Privacy",
    },
    {
        class: "android.app.ApplicationPackageManager",
        method: "getInstalledPackages",
        params: ["int"],
        category: "Privacy",
    },
    // LocationManager
    {
        class: "android.location.LocationManager",
        method: "getLastKnownLocation",
        params: ["java.lang.String"],
        category: "Privacy",
    },
    {
        class: "android.location.LocationManager",
        method: "requestLocationUpdates",
        category: "Privacy",
    },
    {
        class: "android.location.LocationManager",
        method: "requestSingleUpdate",
        category: "Privacy",
    },
    {
        class: "android.location.LocationManager",
        method: "getCurrentLocation",
        category: "Privacy",
    },
    // AccountManager
    {
        class: "android.accounts.AccountManager",
        method: "getAccounts",
        category: "Privacy",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsByType",
        category: "Privacy",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsAndVisibilityForPackage",
        category: "Privacy",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsByTypeAndFeatures",
        category: "Privacy",
    },
    {
        class: "android.accounts.AccountManager",
        method: "getAccountsByTypeForPackage",
        category: "Privacy",
    },
    // Cell location
    {
        class: "android.telephony.TelephonyManager",
        method: "getAllCellInfo",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getCellLocation",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getNeighboringCellInfo",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "listen",
        category: "Privacy",
    },
    // Wifi location
    {
        class: "android.net.wifi.WifiManager",
        method: "getScanResults",
        category: "Privacy",
    },
    {
        class: "android.net.wifi.WifiManager",
        method: "getConnectionInfo",
        category: "Privacy",
    },
    {
        class: "android.net.wifi.WifiManager",
        method: "getConfiguredNetworks",
        category: "Privacy",
    },
    // Device IDs
    {
        class: "android.telephony.TelephonyManager",
        method: "getDeviceId",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getImei",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getMeid",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getSimSerialNumber",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getSubscriberId",
        category: "Privacy",
    },
    // Audio
    {
        class: "android.media.AudioRecord",
        method: "startRecording",
        category: "Privacy",
    },
    // Camera
    {
        class: "android.hardware.camera2.CameraManager",
        method: "openCamera",
        category: "Privacy",
    },
    {
        class: "android.hardware.Camera",
        method: "open",
        category: "Privacy",
    },
    // Phone number
    {
        class: "android.telecom.TelecomManager",
        method: "getLine1Number",
        category: "Privacy",
    },
    {
        class: "android.telephony.TelephonyManager",
        method: "getLine1Number",
        category: "Privacy",
    },
    // ContentResolver: Contact, Sms, Calendar, etc.
    {
        class: "android.app.ContextImpl$ApplicationContentResolver",
        method: "query",
        params_log: [
            {
                location: 0,
                method: "toString"
            }
        ],
        category: "Privacy",
    },
    // Dex loaders
    {
        class: "dalvik.system.BaseDexClassLoader",
        method: "$init",
        params_log: [
            {
                location: 0,
                method: "toString"
            }
        ],
        category: "Security",
    },
    {
        class: "dalvik.system.DexClassLoader",
        method: "$init",
        params_log: [
            {
                location: 0,
                method: "toString"
            }
        ],
        category: "Security",
    },
    {
        class: "dalvik.system.PathClassLoader",
        method: "$init",
        params: [
            "java.lang.String",
            "java.lang.ClassLoader",
        ],
        params_log: [
            {
                location: 0,
                method: "toString",
            },
        ],
        category: "Security",
    },
    // So loaders
    // {
    //     class: "java.lang.System",
    //     method: "load",
    //     params: [
    //         "java.lang.String"
    //     ],
    //     params_log: [
    //         {
    //             location: 0,
    //             method: "toString"
    //         }
    //     ],
    //     category: "Security",
    // },
    // {
    //     class: "java.lang.Runtime",
    //     method: "load",
    //     params: [
    //         "java.lang.String"
    //     ],
    //     params_log: [
    //         {
    //             location: 0,
    //             method: "toString"
    //         }
    //     ],
    //     category: "Security",
    // },
    // Socket server
    {
        class: "java.net.ServerSocket",
        method: "$init",
        category: "Security",
    },
    // Network
    {
        class: "java.net.URL",
        method: "openConnection",
        params_log: [
            {
                location: -1,
                method: "toString"
            }
        ],
        category: "Privacy",
    },
    {
        class: "android.net.Network",
        method: "openConnection",
        category: "Privacy",
    },
    // Shell command
    {
        class: "java.lang.Runtime",
        method: "exec",
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ],
        category: "Security",
    },
    // File
    {
        class: "android.content.ContextImpl",
        method: "openFileInput",
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ],
        category: "Security",
    },
    {
        class: "android.content.Context",
        method: "openOrCreateDatabase",
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ],
        category: "Security",
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
        ],
        category: "Security",
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
        ],
        category: "Security",
    },
    {
        class: "java.io.FileOutputStream",
        method: "$init",
        params: [
            "java.lang.String"
        ],
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ],
        category: "Security",
    },
    {
        class: "java.io.FileOutputStream",
        method: "$init",
        params: [
            "java.lang.String",
            "boolean"
        ],
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ],
        category: "Security",
    },
    {
        class: "java.io.FileOutputStream",
        method: "$init",
        params: [
            "java.io.File",
            "boolean"
        ],
        params_log: [
            {
                location: 0,
                method: "getCanonicalPath"
            },
        ],
        category: "Security",
    },
    {
        class: "java.io.FileOutputStream",
        method: "$init",
        params: [
            "java.io.File"
        ],
        params_log: [
            {
                location: 0,
                method: "getCanonicalPath"
            },
        ],
        category: "Security",
    },
    {
        class: "java.io.RandomAccessFile",
        method: "$init",
        params: [
            "java.lang.String",
            "java.lang.String"
        ],
        params_log: [
            {
                location: 0,
                method: "toString"
            },
        ],
        category: "Security",
    },
    {
        class: "java.io.RandomAccessFile",
        method: "$init",
        params: [
            "java.io.File",
            "java.lang.String"
        ],
        params_log: [
            {
                location: 0,
                method: "getCanonicalPath"
            },
        ],
        category: "Security",
    }
];
export { AspectConfig, gAspects, is_valid_config };
