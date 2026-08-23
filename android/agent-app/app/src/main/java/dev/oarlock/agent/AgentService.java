package dev.oarlock.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.os.Looper;

import dev.oarlock.mobile.oarlockagent.Agent;
import dev.oarlock.mobile.oarlockagent.Listener;
import dev.oarlock.mobile.oarlockagent.Oarlockagent;

public final class AgentService extends Service implements Listener {
    public static final String ACTION_START = "dev.oarlock.agent.START";
    public static final String ACTION_STOP = "dev.oarlock.agent.STOP";
    public static final String PREFS = "agent";
    public static final String KEY_STATUS = "status";
    public static final String KEY_DETAIL = "detail";
    public static final String KEY_LOG = "log";

    private static final String CHANNEL = "oarlock-control";
    private static final int NOTIFICATION_ID = 4821;
    private Agent agent;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(
                CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopAgent(true);
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, notification("Starting"));
        if (agent != null && agent.isRunning()) {
            return START_STICKY;
        }

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        String gateway = value(intent, prefs, "gateway");
        String device = value(intent, prefs, "device");
        String shell = value(intent, prefs, "shell");
        String pins = value(intent, prefs, "pins");
        boolean insecure = intent == null
                ? prefs.getBoolean("insecure", false)
                : intent.getBooleanExtra("insecure", false);
        String keyPath = getFilesDir().getAbsolutePath() + "/device.key";

        try {
            Oarlockagent.ensureKey(keyPath);
            agent = Oarlockagent.newAgent(gateway, device, keyPath, shell, pins, insecure, this);
            agent.start();
            return START_STICKY;
        } catch (Exception error) {
            onStatus("failed", error.getMessage() == null ? error.toString() : error.getMessage());
            stopSelf();
            return START_NOT_STICKY;
        }
    }

    @Override
    public void onStatus(String state, String detail) {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putString(KEY_STATUS, state)
                .putString(KEY_DETAIL, detail)
                .apply();
        getSystemService(NotificationManager.class)
                .notify(NOTIFICATION_ID, notification(state + (detail.isEmpty() ? "" : ": " + detail)));
        if ("stopped".equals(state) || "failed".equals(state)) {
            new android.os.Handler(Looper.getMainLooper()).post(this::stopSelf);
        }
    }

    @Override
    public void onLog(String line) {
        if (line == null || line.isEmpty()) return;
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        String current = prefs.getString(KEY_LOG, "");
        String next = current.isEmpty() ? line : current + "\n" + line;
        if (next.length() > 12000) next = next.substring(next.length() - 12000);
        prefs.edit().putString(KEY_LOG, next).apply();
        if (line.contains("control channel up")) onStatus("connected", "Control channel is up");
    }

    @Override
    public void onDestroy() {
        stopAgent(false);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void stopAgent(boolean updateStatus) {
        Agent current = agent;
        agent = null;
        if (current != null) current.stop();
        if (updateStatus) {
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString(KEY_STATUS, "stopped")
                    .putString(KEY_DETAIL, "Stopped on this headset")
                    .apply();
        }
    }

    private Notification notification(String text) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent content = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Intent stop = new Intent(this, AgentService.class).setAction(ACTION_STOP);
        PendingIntent stopAction = PendingIntent.getService(this, 1, stop,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle("Oarlock Agent")
                .setContentText(text)
                .setContentIntent(content)
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(null, "Stop", stopAction).build())
                .build();
    }

    private static String value(Intent intent, SharedPreferences prefs, String key) {
        String value = intent == null ? null : intent.getStringExtra(key);
        return value == null ? prefs.getString(key, "") : value;
    }
}
