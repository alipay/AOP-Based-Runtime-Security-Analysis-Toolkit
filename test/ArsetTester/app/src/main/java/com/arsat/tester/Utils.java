package com.arsat.tester;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.os.Environment;
import android.telephony.TelephonyManager;
import android.util.Log;

import java.io.File;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;

public class Utils {
    private static final String TAG = "Utils";
    private static final String ARSAT_DIR = "arsat";

    private static File sArsatDir;

    synchronized static public File getArsatDir(Context context) {
        if (sArsatDir == null) {
            File external = Environment.getExternalStorageDirectory();
            File arsatDir = new File(external, ARSAT_DIR);
            if (!arsatDir.exists()) {
                arsatDir.mkdirs();
            }
            sArsatDir = arsatDir;
        }
        return sArsatDir;
    }

    static public void uploadInfo(final String url) {
        new Thread() {
            public void run() {
                try {
                    URL targetUrl = new URL(url);
                    URLConnection conn = targetUrl.openConnection();
                    Log.d(TAG, conn.getContentEncoding());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }
}
