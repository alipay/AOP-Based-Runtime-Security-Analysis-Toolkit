package com.arsat.tester;

import android.Manifest;
import android.app.Activity;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;

import androidx.core.app.ActivityCompat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.UUID;

public class EditorActivity extends Activity {
    public static final String EXTRA_TITLE = "extra_title";
    private static final String TAG = "NewNoteActivity";
    private EditText mEditText;
    private String mTitle;
    LocationManager mLocMgr;

    @Override
    public void onCreate(Bundle savedInstance) {
        super.onCreate(savedInstance);
        setContentView(R.layout.activity_new_note);
        mEditText = (EditText) findViewById(R.id.editor);
        Intent intent = getIntent();
        mLocMgr = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        mTitle = intent.getStringExtra(EXTRA_TITLE);
        if (mTitle != null) {
            restoreNote();
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        try {
            CharSequence cs = cm.getText();
            Log.d(TAG, cs.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        saveNote();
    }

    private void restoreNote() {
        File arsatDir = Utils.getArsatDir(this);
        try {
            File file = new File(arsatDir, mTitle);
            long size = file.length();
            FileInputStream is = new FileInputStream(file);
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[(int)size];
            int count = is.read(buf);
            String content = new String(buf, 0, count);
            mEditText.setText(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void saveNote() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED && ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "no permission, not save");
            return;
        }

        Location loc = mLocMgr.getLastKnownLocation(LocationManager.GPS_PROVIDER);
        String content = mEditText.getText().toString();
        if (content == null || content.length() == 0) {
            Log.d(TAG, "No content, not save");
            return;
        }
        if (mTitle == null) {
            mTitle = generateTitle(content, loc);
        }
        File arsatDir = Utils.getArsatDir(this);
        try {
            File file = new File(arsatDir, mTitle);
            FileOutputStream os = new FileOutputStream(file);
            os.write(content.getBytes());
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String generateTitle(String content, Location loc) {
        String locStr = "unknown";
        if (loc != null) {
            locStr = String.valueOf(loc.getLatitude());
            if (locStr.length() > 4) {
                locStr = locStr.substring(0, 4);
            }
        }
        String title = UUID.randomUUID().toString().substring(0, 8) + locStr;
        return title;
    }
}
