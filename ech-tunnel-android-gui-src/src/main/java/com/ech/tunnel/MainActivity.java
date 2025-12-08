/*
 ============================================================================
 Name        : MainActivity.java
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 xyz
 Description : Main Activity
 ============================================================================
 */

package com.ech.tunnel;

import android.os.Bundle;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.Context;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class MainActivity extends Activity implements View.OnClickListener {
	private Preferences prefs;
    private Spinner spinner_profiles;
    private Button btn_add_profile;
    private Button btn_save_profile;
    private Button btn_rename_profile;
    private Button btn_delete_profile;
    private EditText edittext_socks_port;
    private EditText edittext_wss_addr;
    private EditText edittext_ech_dns;
    private EditText edittext_ech_domain;
    private EditText edittext_pref_ip;
    private EditText edittext_token;
    private EditText edittext_ws_conn;
    private CheckBox checkbox_global;
    private CheckBox checkbox_disable_ech;
    // IPv4/IPv6 默认启用，不在 UI 展示
    private Button button_apps;
    private Button button_control;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		prefs = new Preferences(this);
		setContentView(R.layout.main);

        spinner_profiles = (Spinner) findViewById(R.id.profile_spinner);
        btn_add_profile = (Button) findViewById(R.id.btn_add_profile);
        btn_save_profile = (Button) findViewById(R.id.btn_save_profile);
        btn_rename_profile = (Button) findViewById(R.id.btn_rename_profile);
        btn_delete_profile = (Button) findViewById(R.id.btn_delete_profile);

        edittext_socks_port = (EditText) findViewById(R.id.socks_port);
        edittext_wss_addr = (EditText) findViewById(R.id.wss_addr);
        edittext_ech_dns = (EditText) findViewById(R.id.ech_dns);
        edittext_ech_domain = (EditText) findViewById(R.id.ech_domain);
        edittext_pref_ip = (EditText) findViewById(R.id.pref_ip);
        edittext_token = (EditText) findViewById(R.id.token);
        edittext_ws_conn = (EditText) findViewById(R.id.ws_conn);
        checkbox_global = (CheckBox) findViewById(R.id.global);
        checkbox_disable_ech = (CheckBox) findViewById(R.id.disable_ech);
        button_apps = (Button) findViewById(R.id.apps);
        button_control = (Button) findViewById(R.id.control);

        btn_add_profile.setOnClickListener(this);
        btn_save_profile.setOnClickListener(this);
        btn_rename_profile.setOnClickListener(this);
        btn_delete_profile.setOnClickListener(this);
        checkbox_global.setOnClickListener(this);
        checkbox_disable_ech.setOnClickListener(this);
        button_apps.setOnClickListener(this);
        button_control.setOnClickListener(this);
        
        initProfileSpinner();
		updateUI();

		/* Request VPN permission */

        Intent intent = VpnService.prepare(MainActivity.this);
		if (intent != null)
		  startActivityForResult(intent, 0);
		else
		  onActivityResult(0, RESULT_OK, null);
	}

    private class ProfileItem {
        String id;
        String name;
        
        ProfileItem(String id, String name) {
            this.id = id;
            this.name = name;
        }
        
        @Override
        public String toString() {
            return name;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ProfileItem that = (ProfileItem) o;
            return id.equals(that.id);
        }
    }

    private void initProfileSpinner() {
        refreshProfileSpinner();
        
        spinner_profiles.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                ProfileItem item = (ProfileItem) parent.getItemAtPosition(position);
                if (!item.id.equals(prefs.getCurrentProfileId())) {
                    savePrefs(); // Save current profile before switching
                    prefs.setCurrentProfileId(item.id);
                    updateUI();
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
    }

    private void refreshProfileSpinner() {
        Set<String> ids = prefs.getProfileIds();
        List<ProfileItem> items = new ArrayList<>();
        String currentId = prefs.getCurrentProfileId();

        for (String id : ids) {
            String name = prefs.getProfileName(id);
            items.add(new ProfileItem(id, name));
        }

        java.util.Collections.sort(items, new java.util.Comparator<ProfileItem>() {
            @Override
            public int compare(ProfileItem a, ProfileItem b) {
                return a.name.compareToIgnoreCase(b.name);
            }
        });

        int selectedIndex = 0;
        for (int i = 0; i < items.size(); i++) {
            if (items.get(i).id.equals(currentId)) {
                selectedIndex = i;
                break;
            }
        }

        ArrayAdapter<ProfileItem> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, items);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner_profiles.setAdapter(adapter);
        spinner_profiles.setSelection(selectedIndex);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if ((result == RESULT_OK) && prefs.getEnable()) {
            // 仅当用户手动启用时才启动服务
            Intent intent = new Intent(this, TProxyService.class);
            startService(intent.setAction(TProxyService.ACTION_CONNECT));
        }
    }

    private void showAddProfileDialog() {
        final EditText input = new EditText(this);
        input.setHint(R.string.dialog_hint_name);
        final AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_add)
            .setView(input)
            .setPositiveButton(R.string.ok, null) // Set null first, override later
            .setNegativeButton(R.string.cancel, null)
            .create();

        dialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface d) {
                Button button = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
                button.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        String name = input.getText().toString().trim();
                        if (name.isEmpty()) {
                            Toast.makeText(MainActivity.this, R.string.toast_name_empty, Toast.LENGTH_SHORT).show();
                            return;
                        }
                        // Check dup name
                        for (String id : prefs.getProfileIds()) {
                            if (prefs.getProfileName(id).equals(name)) {
                                Toast.makeText(MainActivity.this, R.string.toast_profile_exists, Toast.LENGTH_SHORT).show();
                                return;
                            }
                        }
                        String newId = UUID.randomUUID().toString();
                        savePrefs(); // Save current before switching
                        prefs.addProfile(newId, name);
                        prefs.setCurrentProfileId(newId);
                        refreshProfileSpinner();
                        updateUI();
                        dialog.dismiss();
                    }
                });
            }
        });
        dialog.show();
    }

    private void showRenameProfileDialog() {
        final String currentId = prefs.getCurrentProfileId();
        final EditText input = new EditText(this);
        input.setText(prefs.getProfileName(currentId));
        new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_rename)
            .setView(input)
            .setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    String name = input.getText().toString().trim();
                    if (!name.isEmpty()) {
                         // Check dup name
                        for (String id : prefs.getProfileIds()) {
                            if (!id.equals(currentId) && prefs.getProfileName(id).equals(name)) {
                                Toast.makeText(MainActivity.this, R.string.toast_profile_exists, Toast.LENGTH_SHORT).show();
                                return;
                            }
                        }
                        prefs.setProfileName(currentId, name);
                        refreshProfileSpinner();
                    }
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    private void deleteCurrentProfile() {
        final String currentId = prefs.getCurrentProfileId();
        Set<String> ids = prefs.getProfileIds();
        if (ids.size() <= 1) {
            Toast.makeText(this, R.string.toast_cannot_delete_last, Toast.LENGTH_SHORT).show();
            return;
        }

        new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_delete)
            .setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    prefs.removeProfile(currentId);
                    // Switch to another one
                    String nextId = prefs.getProfileIds().iterator().next();
                    prefs.setCurrentProfileId(nextId);
                    refreshProfileSpinner();
                    updateUI();
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

	@Override
	public void onClick(View view) {
        if (view == checkbox_global) {
            savePrefs();
            updateUI();
        } else if (view == checkbox_disable_ech) {
            savePrefs();
            updateUI();
        } else if (view == button_apps) {
            startActivity(new Intent(this, AppListActivity.class));
        } else if (view == btn_add_profile) {
            showAddProfileDialog();
        } else if (view == btn_save_profile) {
            String wssAddr = edittext_wss_addr.getText().toString().trim();
            if (wssAddr.isEmpty()) {
                Toast.makeText(this, "服务器地址不能为空", Toast.LENGTH_SHORT).show();
                return;
            }
            savePrefs();
            Toast.makeText(this, R.string.toast_saved, Toast.LENGTH_SHORT).show();
        } else if (view == btn_rename_profile) {
            showRenameProfileDialog();
        } else if (view == btn_delete_profile) {
            deleteCurrentProfile();
        } else if (view == button_control) {
            boolean isEnable = prefs.getEnable();
            if (isEnable) {
                prefs.setEnable(false);
                updateUI();
                // 停用：先发 DISCONNECT，再延迟 200ms 发送一个 stopSelf
                startService(new Intent(this, TProxyService.class).setAction(TProxyService.ACTION_DISCONNECT));
            } else {
                String wssAddr = edittext_wss_addr.getText().toString().trim();
                if (wssAddr.isEmpty()) {
                    Toast.makeText(this, "服务器地址不能为空", Toast.LENGTH_SHORT).show();
                    return;
                }
                savePrefs();
                prefs.setEnable(true);
                updateUI();
                startService(new Intent(this, TProxyService.class).setAction(TProxyService.ACTION_CONNECT));
            }
        }
	}

	private void updateUI() {
        edittext_socks_port.setText(Integer.toString(prefs.getSocksPort()));
        edittext_wss_addr.setText(prefs.getWssAddr());
        edittext_ech_dns.setText(prefs.getEchDns());
        edittext_ech_domain.setText(prefs.getEchDomain());
        edittext_pref_ip.setText(prefs.getPrefIp());
        edittext_token.setText(prefs.getToken());
        edittext_ws_conn.setText(Integer.toString(prefs.getWsConn()));
		checkbox_global.setChecked(prefs.getGlobal());
        checkbox_disable_ech.setChecked(prefs.getDisableEch());

        boolean editable = !prefs.getEnable();
        edittext_socks_port.setEnabled(editable);
        edittext_wss_addr.setEnabled(editable);
        edittext_ech_dns.setEnabled(editable);
        edittext_ech_domain.setEnabled(editable);
        edittext_pref_ip.setEnabled(editable);
        edittext_token.setEnabled(editable);
        edittext_ws_conn.setEnabled(editable);
        checkbox_global.setEnabled(editable);
        checkbox_disable_ech.setEnabled(editable);
        
        boolean globalChecked = checkbox_global.isChecked();
        button_apps.setEnabled(editable && !globalChecked);
        if (button_apps.isEnabled()) {
             button_apps.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF9C27B0)); // Purple
        } else {
             button_apps.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFBDBDBD)); // Grey
        }
        
        spinner_profiles.setEnabled(editable);
        btn_add_profile.setEnabled(editable);
        btn_save_profile.setEnabled(editable);
        btn_rename_profile.setEnabled(editable);
        btn_delete_profile.setEnabled(editable);

        int grey = 0xFFBDBDBD;
        spinner_profiles.setAlpha(editable ? 1.0f : 0.5f);
        btn_add_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFF4CAF50 : grey));
        btn_save_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFF2196F3 : grey));
        btn_rename_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFFFF9800 : grey));
        btn_delete_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFFF44336 : grey));

        if (editable) {
          button_control.setText(R.string.control_enable);
          button_control.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF4CAF50)); // Green
        } else {
          button_control.setText(R.string.control_disable);
          button_control.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFF44336)); // Red
        }
	}

	private void savePrefs() {
        int port = 1080;
        try {
            port = Integer.parseInt(edittext_socks_port.getText().toString());
        } catch (Exception e) {
        }
        if (port < 1024) {
            port = 1024;
            edittext_socks_port.setText(Integer.toString(port));
            Toast.makeText(getApplicationContext(), "端口已设置为≥1024", Toast.LENGTH_SHORT).show();
        }
        prefs.setSocksPort(port);
        prefs.setWssAddr(edittext_wss_addr.getText().toString());
        prefs.setEchDns(edittext_ech_dns.getText().toString());
        prefs.setEchDomain(edittext_ech_domain.getText().toString());
        prefs.setPrefIp(edittext_pref_ip.getText().toString());
        prefs.setToken(edittext_token.getText().toString());
		try {
			prefs.setWsConn(Integer.parseInt(edittext_ws_conn.getText().toString()));
		} catch (Exception e) {
			prefs.setWsConn(prefs.getWsConn());
		}
        // IPv4/IPv6 默认启用
        prefs.setIpv4(true);
        prefs.setIpv6(true);
		prefs.setGlobal(checkbox_global.isChecked());
        prefs.setDisableEch(checkbox_disable_ech.isChecked());
        prefs.setUdpInTcp(false);
        prefs.setRemoteDns(true);
    }
}
