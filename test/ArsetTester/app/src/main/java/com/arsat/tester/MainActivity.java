package com.arsat.tester;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "ArsatTest";

    private ExecutorService mExecutor = Executors.newCachedThreadPool();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    static class MyThread extends Thread {
        private Context mContext;
        public MyThread(Context context) {
            mContext = context;
        }
        @Override
        public void run() {
            testFile(mContext);
        }
    }

    static class MyCallable<T> implements Callable {
        private Context mContext;
        public MyCallable(Context context) {
            mContext = context;
        }
        @Override
        public T call() throws Exception {
            testFile(mContext);
            return null;
        }
    }
    static class MyRunnable implements Runnable {
        private Context mContext;
        public MyRunnable(Context context) {
            mContext = context;
        }
        @Override
        public void run() {
            testFile(mContext);
        }
    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.new_thread:
                startThread(new Thread(new MyRunnable(this)));
                break;
            case R.id.new_custom_thread:
                startThread(new MyThread(this));
                break;
            case R.id.executor_service_execute:
                execute(this, mExecutor);
                break;
            case R.id.executor_service_submit_runnable:
                submit(new MyRunnable(this), mExecutor);
                break;
            case R.id.executor_service_submit_callable:
                submit(new MyCallable<Integer>(this), mExecutor);
                break;
            case R.id.getinstalledpackages:
                getInstalledPackages();
                break;
        }
    }

    private void getInstalledPackages() {
        PackageManager pm = getPackageManager();
        List<PackageInfo> info = pm.getInstalledPackages(0);
        Log.d(TAG, info.size() + " packages");
    }

    private void submit(Object obj, ExecutorService executor) {
        if (obj instanceof MyRunnable) {
            executor.submit((Runnable) obj);
        } else if (obj instanceof Callable) {
            executor.submit((Callable) obj);
        }
    }

    private static void execute(final Context context, Executor executor) {
        executor.execute(new Runnable() {
            @Override
            public void run() {
                testFile(context);
            }
        });
    }

    private static void startThread(Thread t) {
        t.start();
    }

    private static void testFile(Context context) {
        try {
            //FileOutputStream out = context.openFileOutput("test", Context.MODE_PRIVATE);
            //out.close();
            File file = new File(context.getFilesDir(), "test");
            file.createNewFile();
            Log.i(TAG, "call File.createNewFile");
        } catch (IOException e) {
            Log.e(TAG, e.toString());
        }
    }
}