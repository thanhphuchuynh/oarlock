package dev.oarlock.agent;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Locale;

import dev.oarlock.mobile.oarlockagent.Oarlockagent;

public final class MainActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private EditText gateway;
    private EditText device;
    private EditText shell;
    private EditText pins;
    private CheckBox insecure;
    private TextView status;
    private TextView publicKey;
    private TextView logs;

    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            SharedPreferences prefs = prefs();
            String state = prefs.getString(AgentService.KEY_STATUS, "stopped");
            String detail = prefs.getString(AgentService.KEY_DETAIL, "Not running");
            status.setText(getString(R.string.status_format, state.toUpperCase(Locale.ROOT), detail));
            logs.setText(prefs.getString(AgentService.KEY_LOG, ""));
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(28), dp(24), dp(28), dp(40));
        scroll.addView(root);

        TextView title = text("Oarlock Agent", 28, Typeface.BOLD);
        root.addView(title);
        status = text("STOPPED  Not running", 14, Typeface.BOLD);
        status.setTextColor(getColor(R.color.accent));
        status.setPadding(0, dp(8), 0, dp(24));
        root.addView(status);

        SharedPreferences prefs = prefs();
        gateway = field(root, "Gateway", prefs.getString("gateway", "ws://192.168.1.10:8443/ws/control"),
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        device = field(root, "Device ID", prefs.getString("device", "vr-headset-01"), InputType.TYPE_CLASS_TEXT);
        shell = field(root, "Shell", prefs.getString("shell", "/system/bin/sh"), InputType.TYPE_CLASS_TEXT);
        pins = field(root, "Certificate pins", prefs.getString("pins", ""), InputType.TYPE_CLASS_TEXT);
        insecure = new CheckBox(this);
        insecure.setText(R.string.insecure_mode);
        insecure.setChecked(prefs.getBoolean("insecure", false));
        insecure.setPadding(0, dp(8), 0, dp(16));
        root.addView(insecure);

        root.addView(text("Device public key", 13, Typeface.BOLD));
        publicKey = text("Generating...", 12, Typeface.MONOSPACE.getStyle());
        publicKey.setTypeface(Typeface.MONOSPACE);
        publicKey.setTextIsSelectable(true);
        publicKey.setPadding(0, dp(8), 0, dp(8));
        root.addView(publicKey);

        Button copy = button("Copy public key");
        copy.setOnClickListener(view -> {
            getSystemService(ClipboardManager.class).setPrimaryClip(
                    ClipData.newPlainText("Oarlock device public key", publicKey.getText()));
            Toast.makeText(this, "Public key copied", Toast.LENGTH_SHORT).show();
        });
        root.addView(copy);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setPadding(0, dp(20), 0, dp(20));
        Button start = button("Start agent");
        Button stop = button("Stop agent");
        actions.addView(start, new LinearLayout.LayoutParams(0, dp(52), 1));
        LinearLayout.LayoutParams stopParams = new LinearLayout.LayoutParams(0, dp(52), 1);
        stopParams.setMarginStart(dp(12));
        actions.addView(stop, stopParams);
        root.addView(actions);

        start.setOnClickListener(view -> startAgent());
        stop.setOnClickListener(view -> stopAgent());

        root.addView(text("Activity log", 13, Typeface.BOLD));
        logs = text("", 11, Typeface.MONOSPACE.getStyle());
        logs.setTypeface(Typeface.MONOSPACE);
        logs.setTextIsSelectable(true);
        logs.setPadding(0, dp(8), 0, 0);
        root.addView(logs);
        setContentView(scroll);

        new Thread(() -> {
            try {
                String key = Oarlockagent.ensureKey(getFilesDir().getAbsolutePath() + "/device.key");
                runOnUiThread(() -> publicKey.setText(key));
            } catch (Exception error) {
                runOnUiThread(() -> publicKey.setText(getString(R.string.key_error, error.getMessage())));
            }
        }).start();
    }

    @Override protected void onResume() {
        super.onResume();
        handler.post(refresh);
    }

    @Override protected void onPause() {
        handler.removeCallbacks(refresh);
        super.onPause();
    }

    private void startAgent() {
        String gatewayValue = gateway.getText().toString().trim();
        String deviceValue = device.getText().toString().trim();
        if ((!gatewayValue.startsWith("ws://") && !gatewayValue.startsWith("wss://")) || deviceValue.isEmpty()) {
            Toast.makeText(this, "Enter a WebSocket gateway URL and device ID", Toast.LENGTH_LONG).show();
            return;
        }
        prefs().edit()
                .putString("gateway", gatewayValue)
                .putString("device", deviceValue)
                .putString("shell", shell.getText().toString().trim())
                .putString("pins", pins.getText().toString().trim())
                .putBoolean("insecure", insecure.isChecked())
                .putString(AgentService.KEY_LOG, "")
                .apply();

        Intent intent = new Intent(this, AgentService.class).setAction(AgentService.ACTION_START)
                .putExtra("gateway", gatewayValue)
                .putExtra("device", deviceValue)
                .putExtra("shell", shell.getText().toString().trim())
                .putExtra("pins", pins.getText().toString().trim())
                .putExtra("insecure", insecure.isChecked());
        startForegroundService(intent);
    }

    private void stopAgent() {
        startService(new Intent(this, AgentService.class).setAction(AgentService.ACTION_STOP));
    }

    private EditText field(LinearLayout parent, String label, String value, int inputType) {
        TextView caption = text(label, 13, Typeface.BOLD);
        caption.setPadding(0, dp(10), 0, dp(5));
        parent.addView(caption);
        EditText input = new EditText(this);
        input.setText(value);
        input.setTextSize(16);
        input.setSingleLine(true);
        input.setInputType(inputType);
        input.setSelectAllOnFocus(false);
        input.setMinHeight(dp(52));
        parent.addView(input, new LinearLayout.LayoutParams(-1, -2));
        return input;
    }

    private TextView text(String value, int size, int style) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(getColor(R.color.foreground));
        view.setTypeface(Typeface.DEFAULT, style);
        return view;
    }

    private Button button(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setMinHeight(dp(48));
        return button;
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(AgentService.PREFS, MODE_PRIVATE);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
