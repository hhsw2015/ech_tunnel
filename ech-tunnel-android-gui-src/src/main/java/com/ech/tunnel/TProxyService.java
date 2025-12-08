/*
 ============================================================================
 Name        : TProxyService.java
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 xyz
 Description : TProxy Service
 ============================================================================
 */

package com.ech.tunnel;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.app.Notification;
import android.app.Notification.Builder;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import com.ech.tunnel.tunnel.Tunnel;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ServiceInfo;

import androidx.core.app.NotificationCompat;

public class TProxyService extends VpnService {
	private static native void TProxyStartService(String config_path, int fd);
	private static native void TProxyStopService();
	private static native long[] TProxyGetStats();

        public static final String ACTION_CONNECT = "com.ech.tunnel.CONNECT";
        public static final String ACTION_DISCONNECT = "com.ech.tunnel.DISCONNECT";

	static {
		System.loadLibrary("hev-socks5-tunnel");
	}

	private ParcelFileDescriptor tunFd = null;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            stopService();
            return START_NOT_STICKY;
        }
        if (tunFd != null) {
            return START_STICKY;
        }
        startService();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

	@Override
	public void onRevoke() {
		stopService();
		super.onRevoke();
	}

    public void startService() {
        if (tunFd != null) { return; }

		Preferences prefs = new Preferences(this);

		/* VPN */
		String session = new String();
        VpnService.Builder builder = new VpnService.Builder();
		builder.setBlocking(false);
		builder.setMtu(prefs.getTunnelMtu());
		if (prefs.getIpv4()) {
			String addr = prefs.getTunnelIpv4Address();
			int prefix = prefs.getTunnelIpv4Prefix();
			String dns = prefs.getDnsIpv4();
			builder.addAddress(addr, prefix);
			builder.addRoute("0.0.0.0", 0);
			if (!prefs.getRemoteDns() && !dns.isEmpty())
			  builder.addDnsServer(dns);
			session += "IPv4";
		}
		if (prefs.getIpv6()) {
			String addr = prefs.getTunnelIpv6Address();
			int prefix = prefs.getTunnelIpv6Prefix();
			String dns = prefs.getDnsIpv6();
			builder.addAddress(addr, prefix);
			builder.addRoute("::", 0);
			if (!prefs.getRemoteDns() && !dns.isEmpty())
			  builder.addDnsServer(dns);
			if (!session.isEmpty())
			  session += " + ";
			session += "IPv6";
		}
		if (prefs.getRemoteDns()) {
			builder.addDnsServer(prefs.getMappedDns());
		}
		boolean disallowSelf = true;
		if (prefs.getGlobal()) {
			session += "/Global";
		} else {
			for (String appName : prefs.getApps()) {
				try {
					builder.addAllowedApplication(appName);
					disallowSelf = false;
				} catch (NameNotFoundException e) {
				}
			}
			session += "/per-App";
		}
		if (disallowSelf) {
			String selfName = getApplicationContext().getPackageName();
			try {
				builder.addDisallowedApplication(selfName);
			} catch (NameNotFoundException e) {
			}
		}
		builder.setSession(session);
        try {
            tunFd = builder.establish();
        } catch (Exception e) {
            stopSelf();
            return;
        }
        if (tunFd == null) {
            stopSelf();
            return;
        }

                // 生成 TProxy 配置并启动原生隧道（VPN）
                File tproxy_file = new File(getCacheDir(), "tproxy.conf");
                try {
                        tproxy_file.createNewFile();
                        FileOutputStream fos = new FileOutputStream(tproxy_file, false);

                        String tproxy_conf = "misc:\n" +
                                "  task-stack-size: " + prefs.getTaskStackSize() + "\n" +
                                "tunnel:\n" +
                                "  mtu: " + prefs.getTunnelMtu() + "\n";

                        tproxy_conf += "socks5:\n" +
                                "  port: " + prefs.getSocksPort() + "\n" +
                                "  address: '" + prefs.getSocksAddress() + "'\n" +
                                "  udp: '" + (prefs.getUdpInTcp() ? "tcp" : "udp") + "'\n";

                        if (!prefs.getSocksUdpAddress().isEmpty()) {
                                tproxy_conf += "  udp-address: '" + prefs.getSocksUdpAddress() + "'\n";
                        }

                        if (!prefs.getSocksUsername().isEmpty() &&
                                !prefs.getSocksPassword().isEmpty()) {
                                tproxy_conf += "  username: '" + prefs.getSocksUsername() + "'\n";
                                tproxy_conf += "  password: '" + prefs.getSocksPassword() + "'\n";
                        }

                        if (prefs.getRemoteDns()) {
                                tproxy_conf += "mapdns:\n" +
                                        "  address: " + prefs.getMappedDns() + "\n" +
                                        "  port: 53\n" +
                                        "  network: 240.0.0.0\n" +
                                        "  netmask: 240.0.0.0\n" +
                                        "  cache-size: 10000\n";
                        }

                        fos.write(tproxy_conf.getBytes());
                        fos.close();
                } catch (IOException e) {
                        return;
                }
                
                // Start TProxy Native Service
                TProxyStartService(tproxy_file.getAbsolutePath(), tunFd.getFd());

                // 同时启动本地 SOCKS5（127.0.0.1:port）并桥接到远端 WSS/ECH
                try {
                        String wsAddr = prefs.getWssAddr().trim();
                        if (!wsAddr.startsWith("wss://")) {
                                wsAddr = "wss://" + wsAddr;
                        }
                        int idx = wsAddr.indexOf("://");
                        if (idx >= 0) {
                                String rest = wsAddr.substring(idx + 3);
                                if (!rest.contains("/")) {
                                        wsAddr = wsAddr + "/";
                                }
                        }
                        Tunnel.startSocksProxy(
                                prefs.getSocksAddress() + ":" + Integer.toString(prefs.getSocksPort()),
                                wsAddr,
                                prefs.getWsConn(),
                                prefs.getEchDns(),
                                prefs.getEchDomain(),
                                prefs.getPrefIp(),
                                prefs.getToken(),
                                prefs.getDisableEch()
                        );
                } catch (Exception e) {
                        try { TProxyStopService(); } catch (Throwable t) {}
                        try { if (tunFd != null) { tunFd.close(); tunFd = null; } } catch (IOException ioe) {}
                        stopSelf();
                        return;
                }
                prefs.setEnable(true);

		String channelName = "socks5";
		initNotificationChannel(channelName);
		createNotification(channelName);
	}

    public void stopService() {
        try { stopForeground(true); } catch (Throwable t) { }
        try { Tunnel.stopSocksProxy(); } catch (Exception e) { }
        try { TProxyStopService(); } catch (Throwable t) { }
        if (tunFd != null) {
            try { tunFd.close(); } catch (IOException e) {}
            tunFd = null;
        }
        System.exit(0);
    }

    private void runWithTimeout(Runnable task, long timeoutMs, String name) {
        Thread th = new Thread(task, name);
        th.start();
        try { th.join(timeoutMs); } catch (InterruptedException ignored) {}
    }

	private void createNotification(String channelName) {
		Intent i = new Intent(this, MainActivity.class);
		i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
		PendingIntent pi = PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE);
		NotificationCompat.Builder notification = new NotificationCompat.Builder(this, channelName);
		Notification notify = notification
				.setContentTitle(getString(R.string.app_name))
				.setSmallIcon(android.R.drawable.sym_def_app_icon)
				.setContentIntent(pi)
				.build();
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
			startForeground(1, notify);
		} else {
			startForeground(1, notify, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
		}
	}

	// create NotificationChannel
	private void initNotificationChannel(String channelName) {
		NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			CharSequence name = getString(R.string.app_name);
			NotificationChannel channel = new NotificationChannel(channelName, name, NotificationManager.IMPORTANCE_DEFAULT);
			notificationManager.createNotificationChannel(channel);
		}
	}
}
