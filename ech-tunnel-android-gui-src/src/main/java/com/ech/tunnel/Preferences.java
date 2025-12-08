/*
 ============================================================================
 Name        : Perferences.java
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 xyz
 Description : Perferences
 ============================================================================
 */

package com.ech.tunnel;

import java.util.Set;
import java.util.HashSet;
import android.content.Context;
import android.content.SharedPreferences;

public class Preferences
{
        public static final String PREFS_NAME = "SocksPrefs";
        public static final String SOCKS_ADDR = "SocksAddr";
        public static final String SOCKS_UDP_ADDR = "SocksUdpAddr";
        public static final String SOCKS_PORT = "SocksPort";
        public static final String SOCKS_USER = "SocksUser";
        public static final String SOCKS_PASS = "SocksPass";
        public static final String DNS_IPV4 = "DnsIpv4";
        public static final String DNS_IPV6 = "DnsIpv6";
        public static final String IPV4 = "Ipv4";
        public static final String IPV6 = "Ipv6";
        public static final String GLOBAL = "Global";
        public static final String UDP_IN_TCP = "UdpInTcp";
        public static final String REMOTE_DNS = "RemoteDNS";
        public static final String APPS = "Apps";
        public static final String ENABLE = "Enable";

        // ECH-tunnel 相关参数
        public static final String WSS_ADDR = "WssAddr";
        public static final String ECH_DNS = "EchDns";
        public static final String ECH_DOMAIN = "EchDomain";
        public static final String PREF_IP = "PrefIp";
        public static final String TOKEN = "Token";
        public static final String WS_CONN = "WsConn";
        public static final String DISABLE_ECH = "DisableEch";
        
        // Profile Management
        public static final String CURRENT_PROFILE_ID = "CurrentProfileId";
        public static final String PROFILES = "Profiles"; // Set<String> of profile IDs
        public static final String PROFILE_NAME_PREFIX = "ProfileName_";

        private SharedPreferences prefs;
        private String currentProfileId; // Current Profile ID (e.g., "default", "uuid...")

        public Preferences(Context context) {
                prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_MULTI_PROCESS);
                initProfiles();
        }

        private void initProfiles() {
            // Load current profile ID
            currentProfileId = prefs.getString(CURRENT_PROFILE_ID, "default");
            
            // Ensure default profile exists in the set
            Set<String> profiles = getProfileIds();
            if (!profiles.contains("default")) {
                addProfile("default", "默认节点");
            }
        }

        // Helper to get key with profile suffix
        private String getKey(String key) {
            return key + "_" + currentProfileId;
        }

        public Set<String> getProfileIds() {
            return prefs.getStringSet(PROFILES, new HashSet<String>(java.util.Collections.singletonList("default")));
        }
        
        public String getCurrentProfileId() {
            return currentProfileId;
        }

        public void setCurrentProfileId(String id) {
            this.currentProfileId = id;
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString(CURRENT_PROFILE_ID, id);
            editor.commit();
        }

        public String getProfileName(String id) {
            if ("default".equals(id)) {
                return prefs.getString(PROFILE_NAME_PREFIX + "default", "默认节点");
            }
            return prefs.getString(PROFILE_NAME_PREFIX + id, "Node " + id);
        }

        public void setProfileName(String id, String name) {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString(PROFILE_NAME_PREFIX + id, name);
            editor.commit();
        }

        public void addProfile(String id, String name) {
            Set<String> profiles = new HashSet<>(getProfileIds());
            profiles.add(id);
            
            SharedPreferences.Editor editor = prefs.edit();
            editor.putStringSet(PROFILES, profiles);
            editor.putString(PROFILE_NAME_PREFIX + id, name);
            editor.commit();
        }

        public void removeProfile(String id) {
            // Logic moved to MainActivity to check size before calling or allow calling freely if size > 1
            // Here we just remove whatever ID is passed, assuming upper layer checked constraints.
            // Previously: if ("default".equals(id)) return; 
            // Now: Allow deleting default if it's not the last one (handled by caller)

            Set<String> profiles = new HashSet<>(getProfileIds());
            if (!profiles.contains(id)) return;

            profiles.remove(id);
            
            SharedPreferences.Editor editor = prefs.edit();
            editor.putStringSet(PROFILES, profiles);
            editor.remove(PROFILE_NAME_PREFIX + id);
            
            // Clean up all keys for this profile
            String[] keys = {WSS_ADDR, ECH_DNS, ECH_DOMAIN, PREF_IP, TOKEN, WS_CONN, DISABLE_ECH};
            for (String k : keys) {
                editor.remove(k + "_" + id);
            }
            editor.commit();
        }

        public String getSocksAddress() {
                return "0.0.0.0";
        }

    public String getSocksUdpAddress() { return ""; }
    public void setSocksUdpAddress(String addr) { }

	public int getSocksPort() {
		return prefs.getInt(SOCKS_PORT, 1080);
	}

	public void setSocksPort(int port) {
		SharedPreferences.Editor editor = prefs.edit();
		editor.putInt(SOCKS_PORT, port);
		editor.commit();
	}

    public String getSocksUsername() { return ""; }
    public void setSocksUsername(String user) { }

    public String getSocksPassword() { return ""; }
    public void setSocksPassword(String pass) { }

    public String getDnsIpv4() { return ""; }
    public void setDnsIpv4(String addr) { }

    public String getDnsIpv6() { return ""; }
    public void setDnsIpv6(String addr) { }

	public String getMappedDns() {
		return "198.18.0.2";
	}

    public boolean getUdpInTcp() { return false; }
    public void setUdpInTcp(boolean enable) { }

    public boolean getRemoteDns() { return true; }
    public void setRemoteDns(boolean enable) { }

	public boolean getIpv4() {
		return prefs.getBoolean(IPV4, true);
	}

	public void setIpv4(boolean enable) {
		SharedPreferences.Editor editor = prefs.edit();
		editor.putBoolean(IPV4, enable);
		editor.commit();
	}

	public boolean getIpv6() {
		return prefs.getBoolean(IPV6, true);
	}

	public void setIpv6(boolean enable) {
		SharedPreferences.Editor editor = prefs.edit();
		editor.putBoolean(IPV6, enable);
		editor.commit();
	}

    public boolean getGlobal() { return prefs.getBoolean(GLOBAL, true); }

	public void setGlobal(boolean enable) {
		SharedPreferences.Editor editor = prefs.edit();
		editor.putBoolean(GLOBAL, enable);
		editor.commit();
	}

	public Set<String> getApps() {
		return prefs.getStringSet(APPS, new HashSet<String>());
	}

	public void setApps(Set<String> apps) {
		SharedPreferences.Editor editor = prefs.edit();
		editor.putStringSet(APPS, apps);
		editor.commit();
	}

	public boolean getEnable() {
		return prefs.getBoolean(ENABLE, false);
	}

	public void setEnable(boolean enable) {
		SharedPreferences.Editor editor = prefs.edit();
		editor.putBoolean(ENABLE, enable);
		editor.commit();
	}

	public int getTunnelMtu() {
		return 8500;
	}

	public String getTunnelIpv4Address() {
		return "198.18.0.1";
	}

	public int getTunnelIpv4Prefix() {
		return 32;
	}

	public String getTunnelIpv6Address() {
		return "fc00::1";
	}

	public int getTunnelIpv6Prefix() {
		return 128;
	}

        public int getTaskStackSize() {
                return 81920;
        }

        // ECH-tunnel: 远端 WSS 地址
        public String getWssAddr() {
                return prefs.getString(getKey(WSS_ADDR), "");
        }

        public void setWssAddr(String addr) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString(getKey(WSS_ADDR), addr);
                editor.commit();
        }

        // ECH-tunnel: DNS 服务器
        public String getEchDns() {
                return prefs.getString(getKey(ECH_DNS), "dns.alidns.com/dns-query");
        }

        public void setEchDns(String addr) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString(getKey(ECH_DNS), addr);
                editor.commit();
        }

        // ECH-tunnel: 域名
        public String getEchDomain() {
                return prefs.getString(getKey(ECH_DOMAIN), "cloudflare-ech.com");
        }

        public void setEchDomain(String d) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString(getKey(ECH_DOMAIN), d);
                editor.commit();
        }

        // ECH-tunnel: 优选 IP
        public String getPrefIp() { return prefs.getString(getKey(PREF_IP), ""); }

        public void setPrefIp(String ip) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString(getKey(PREF_IP), ip);
                editor.commit();
        }

        // ECH-tunnel: 子协议令牌
        public String getToken() { return prefs.getString(getKey(TOKEN), ""); }

        public void setToken(String t) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString(getKey(TOKEN), t);
                editor.commit();
        }

        // ECH-tunnel: WebSocket 连接数
        public int getWsConn() {
                return prefs.getInt(getKey(WS_CONN), 3);
        }

        public void setWsConn(int n) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putInt(getKey(WS_CONN), n);
                editor.commit();
        }

        // ECH-tunnel: 禁用 ECH
        public boolean getDisableEch() {
                return prefs.getBoolean(getKey(DISABLE_ECH), false);
        }

        public void setDisableEch(boolean disable) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putBoolean(getKey(DISABLE_ECH), disable);
                editor.commit();
        }
}
