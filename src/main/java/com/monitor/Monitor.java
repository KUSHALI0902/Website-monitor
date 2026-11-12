package com.monitor;

import com.sun.management.OperatingSystemMXBean;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Monitor {

    // --- Data Models ---

    public static class Point {
        public final long ms;
        public final String time;
        public final boolean up;

        public Point(long ms, String time, boolean up) {
            this.ms = ms;
            this.time = time;
            this.up = up;
        }
    }

    public static class SiteStats {
        public long totalChecks = 0;
        public long successfulChecks = 0;
        public long totalResponseTimeMs = 0;
        public long minResponseTimeMs = Long.MAX_VALUE;
        public long maxResponseTimeMs = 0;

        public synchronized void record(boolean up, long ms) {
            totalChecks++;
            if (up) {
                successfulChecks++;
                totalResponseTimeMs += ms;
                if (ms < minResponseTimeMs) minResponseTimeMs = ms;
                if (ms > maxResponseTimeMs) maxResponseTimeMs = ms;
            }
        }

        public synchronized double uptimePercent() {
            if (totalChecks == 0) return 100.0;
            return (successfulChecks * 100.0) / totalChecks;
        }

        public synchronized long avgMs() {
            if (successfulChecks == 0) return 0;
            return totalResponseTimeMs / successfulChecks;
        }

        public synchronized long minMs() {
            return minResponseTimeMs == Long.MAX_VALUE ? 0 : minResponseTimeMs;
        }
    }

    public static class Status {
        public String url;
        public String name;
        public int intervalSec;
        public boolean up;
        public int code;
        public long ms;
        public String checkedAt;
        public String error;
        public Integer sslDaysRemaining;
        public long lastSslCheckedTime = 0;
        public final SiteStats stats = new SiteStats();
        public final List<Point> history = new CopyOnWriteArrayList<>();

        public Status(String url, String name, int intervalSec) {
            this.url = url;
            this.name = (name == null || name.isBlank()) ? url : name;
            this.intervalSec = intervalSec <= 0 ? 10 : intervalSec;
        }

        public synchronized void addPoint(Point p) {
            history.add(p);
            while (history.size() > 10) {
                history.remove(0);
            }
        }
    }

    // --- State & Schedulers ---

    static final Map<String, Status> statuses = new ConcurrentHashMap<>();
    static final Map<String, ScheduledFuture<?>> tasks = new ConcurrentHashMap<>();
    static final List<String> alerts = new CopyOnWriteArrayList<>();
    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(4);

    static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    static final OperatingSystemMXBean os =
            (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

    // --- System Resource Metrics ---

    static double cpuPercent() {
        double v = os.getCpuLoad();
        return (Double.isNaN(v) || v < 0) ? 0.0 : v * 100.0;
    }

    static double memPercent() {
        long total = os.getTotalMemorySize();
        long free = os.getFreeMemorySize();
        return total <= 0 ? 0.0 : (total - free) * 100.0 / total;
    }

    // --- SSL Certificate Inspection ---

    static Integer checkSslDays(String urlStr) {
        if (urlStr == null || !urlStr.toLowerCase().startsWith("https://")) return null;
        try {
            URI uri = URI.create(urlStr);
            String host = uri.getHost();
            if (host == null) return null;
            int port = uri.getPort() > 0 ? uri.getPort() : 443;

            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, port), 5000);
                socket.startHandshake();
                SSLSession session = socket.getSession();
                Certificate[] certs = session.getPeerCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    Date notAfter = x509.getNotAfter();
                    long diffMs = notAfter.getTime() - System.currentTimeMillis();
                    return (int) Math.max(0, TimeUnit.MILLISECONDS.toDays(diffMs));
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // --- Health Check ---

    static void check(String url) {
        Status s = statuses.get(url);
        if (s == null) return;

        boolean wasUp = s.stats.totalChecks == 0 || s.up;
        s.checkedAt = LocalDateTime.now().format(FMT);
        String shortTime = LocalDateTime.now().format(TIME_FMT);
        long start = System.currentTimeMillis();

        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<Void> res = client.send(req, HttpResponse.BodyHandlers.discarding());
            s.code = res.statusCode();
            s.up = s.code < 400;
            s.error = s.up ? null : "HTTP " + s.code;
        } catch (Exception e) {
            s.code = 0;
            s.up = false;
            String msg = e.getMessage();
            s.error = e.getClass().getSimpleName() + (msg != null && !msg.isBlank() ? ": " + msg : "");
        }
        s.ms = System.currentTimeMillis() - start;
        s.stats.record(s.up, s.ms);
        s.addPoint(new Point(s.ms, shortTime, s.up));

        // Inspect SSL certificate once every 2 hours
        long now = System.currentTimeMillis();
        if (url.toLowerCase().startsWith("https://") && (now - s.lastSslCheckedTime > 7_200_000 || s.sslDaysRemaining == null)) {
            s.sslDaysRemaining = checkSslDays(url);
            s.lastSslCheckedTime = now;
        }

        // Trigger Alerts
        if (wasUp && !s.up) {
            String detail = s.code > 0 ? "HTTP " + s.code : (s.error != null ? s.error : "Connection failed");
            alert("DOWN", s.name + " (" + url + ")", detail);
        } else if (!wasUp && s.up) {
            alert("RECOVERED", s.name + " (" + url + ")", "back online in " + s.ms + " ms");
        }
    }

    // --- Alerts & Webhook ---

    static void alert(String type, String target, String detail) {
        String msg = "[" + LocalDateTime.now().format(FMT) + "] " + type + ": " + target + " (" + detail + ")";
        System.out.println("*** ALERT *** " + msg);

        synchronized (alerts) {
            alerts.add(0, msg);
            while (alerts.size() > 30) {
                alerts.remove(alerts.size() - 1);
            }
        }

        sendWebhook(type, target, detail, msg);
    }

    static void sendWebhook(String type, String target, String detail, String fullMsg) {
        String webhookUrl = System.getenv("WEBHOOK_URL");
        if (webhookUrl == null || webhookUrl.isBlank()) return;

        try {
            String color = "DOWN".equals(type) ? "15158332" : "3066993";
            String payload = "{"
                    + "\"content\":\"" + escapeJson(fullMsg) + "\","
                    + "\"text\":\"" + escapeJson(fullMsg) + "\","
                    + "\"embeds\":[{"
                    + "\"title\":\"Website Status: " + escapeJson(type) + "\","
                    + "\"description\":\"**Site:** " + escapeJson(target) + "\\n**Details:** " + escapeJson(detail) + "\","
                    + "\"color\":" + color
                    + "}]}";

            HttpRequest req = HttpRequest.newBuilder(URI.create(webhookUrl))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                    .build();

            client.sendAsync(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            System.err.println("Webhook dispatch failed: " + e.getMessage());
        }
    }

    // --- Dynamic Site Management ---

    public static synchronized String registerSite(String url, String name, int intervalSec) {
        if (url == null || url.isBlank()) return "URL cannot be empty";
        url = url.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }

        try {
            URI u = URI.create(url);
            if (u.getHost() == null || u.getHost().isBlank()) {
                return "Invalid URL: missing host";
            }
        } catch (Exception e) {
            return "Invalid URL format: " + e.getMessage();
        }

        if (statuses.containsKey(url)) {
            return "Website is already being monitored: " + url;
        }

        String displayName = (name == null || name.isBlank()) ? url : name.trim();
        Status s = new Status(url, displayName, intervalSec <= 0 ? 10 : intervalSec);
        statuses.put(url, s);

        final String siteUrl = url;
        ScheduledFuture<?> future = scheduler.scheduleWithFixedDelay(() -> {
            try {
                check(siteUrl);
            } catch (Throwable t) {
                System.err.println("Check error for " + siteUrl + ": " + t.getMessage());
            }
        }, 0, s.intervalSec, TimeUnit.SECONDS);

        tasks.put(url, future);
        return null; // success
    }

    public static synchronized void unregisterSite(String url) {
        if (url == null) return;
        url = url.trim();
        ScheduledFuture<?> future = tasks.remove(url);
        if (future != null) {
            future.cancel(true);
        }
        statuses.remove(url);
    }

    // --- Helpers ---

    static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    static String escapePrometheus(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n");
    }

    static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    // --- Prometheus Metrics (Raw Exposition 0.0.4) ---

    static String metrics() {
        StringBuilder sb = new StringBuilder();

        sb.append("# HELP website_up Whether the website is reachable and HTTP status < 400 (1 = UP, 0 = DOWN)\n");
        sb.append("# TYPE website_up gauge\n");
        for (Status s : statuses.values()) {
            sb.append("website_up{url=\"").append(escapePrometheus(s.url)).append("\",name=\"")
              .append(escapePrometheus(s.name)).append("\"} ").append(s.up ? 1 : 0).append("\n");
        }

        sb.append("# HELP website_response_ms Website response time in milliseconds\n");
        sb.append("# TYPE website_response_ms gauge\n");
        for (Status s : statuses.values()) {
            sb.append("website_response_ms{url=\"").append(escapePrometheus(s.url)).append("\",name=\"")
              .append(escapePrometheus(s.name)).append("\"} ").append(s.ms).append("\n");
        }

        sb.append("# HELP website_uptime_percent Historical uptime percentage\n");
        sb.append("# TYPE website_uptime_percent gauge\n");
        for (Status s : statuses.values()) {
            sb.append("website_uptime_percent{url=\"").append(escapePrometheus(s.url)).append("\",name=\"")
              .append(escapePrometheus(s.name)).append("\"} ")
              .append(String.format(Locale.US, "%.2f", s.stats.uptimePercent())).append("\n");
        }

        sb.append("# HELP website_ssl_days_remaining Days until SSL certificate expiration\n");
        sb.append("# TYPE website_ssl_days_remaining gauge\n");
        for (Status s : statuses.values()) {
            if (s.sslDaysRemaining != null) {
                sb.append("website_ssl_days_remaining{url=\"").append(escapePrometheus(s.url)).append("\",name=\"")
                  .append(escapePrometheus(s.name)).append("\"} ").append(s.sslDaysRemaining).append("\n");
            }
        }

        sb.append("# HELP system_cpu_percent System CPU usage percentage\n");
        sb.append("# TYPE system_cpu_percent gauge\n");
        sb.append("system_cpu_percent ").append(String.format(Locale.US, "%.2f", cpuPercent())).append("\n");

        sb.append("# HELP system_memory_used_percent System memory usage percentage\n");
        sb.append("# TYPE system_memory_used_percent gauge\n");
        sb.append("system_memory_used_percent ").append(String.format(Locale.US, "%.2f", memPercent())).append("\n");

        return sb.toString();
    }

    // --- Prometheus Metrics HTML Inspector ---

    static String metricsHtml() {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
          .append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
          .append("<title>WebPulse - Prometheus Metrics</title>")
          .append("<style>")
          .append("body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px 32px; }")
          .append(".header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid #334155; }")
          .append("h1 { font-size: 22px; color: #38bdf8; }")
          .append(".btn { background: #1e293b; border: 1px solid #334155; color: #f8fafc; padding: 8px 14px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }")
          .append(".btn:hover { background: #334155; }")
          .append(".card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin-bottom: 20px; }")
          .append("table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; font-family: monospace; }")
          .append("th { background: #0f172a; padding: 10px 14px; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }")
          .append("td { padding: 10px 14px; border-bottom: 1px solid #334155; }")
          .append(".val { font-weight: 700; color: #38bdf8; }")
          .append(".help-text { font-size: 12px; color: #94a3b8; margin-bottom: 10px; font-style: italic; }")
          .append(".info-banner { background: #0369a1; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; font-size: 13px; }")
          .append("</style></head><body>");

        sb.append("<div class='header'>")
          .append("<h1>📈 Prometheus Metrics Feed</h1>")
          .append("<div style='display:flex;gap:10px;'>")
          .append("<a href='/' class='btn'>⬅ Dashboard</a>")
          .append("<a href='/metrics?format=raw' class='btn' target='_blank'>📄 Raw Prometheus Text</a>")
          .append("</div></div>");

        sb.append("<div class='info-banner'>")
          .append("💡 This page displays Prometheus metrics in a human-readable inspector. ")
          .append("Automated scrapers (like Prometheus on <code>http://localhost:9090</code>) receive the exact Prometheus text format automatically from this URL.")
          .append("</div>");

        // Metrics Table
        sb.append("<div class='card'><h2>Exposed Metric Families</h2>");
        sb.append("<table><thead><tr><th>Metric Name</th><th>Labels</th><th>Value</th><th>Type</th></tr></thead><tbody>");

        for (Status s : statuses.values()) {
            sb.append("<tr><td>website_up</td><td>url=\"").append(escapeHtml(s.url)).append("\"</td><td class='val'>")
              .append(s.up ? "1 (UP)" : "0 (DOWN)").append("</td><td>gauge</td></tr>");
            sb.append("<tr><td>website_response_ms</td><td>url=\"").append(escapeHtml(s.url)).append("\"</td><td class='val'>")
              .append(s.ms).append(" ms</td><td>gauge</td></tr>");
            sb.append("<tr><td>website_uptime_percent</td><td>url=\"").append(escapeHtml(s.url)).append("\"</td><td class='val'>")
              .append(String.format(Locale.US, "%.2f%%", s.stats.uptimePercent())).append("</td><td>gauge</td></tr>");
            if (s.sslDaysRemaining != null) {
                sb.append("<tr><td>website_ssl_days_remaining</td><td>url=\"").append(escapeHtml(s.url)).append("\"</td><td class='val'>")
                  .append(s.sslDaysRemaining).append(" days</td><td>gauge</td></tr>");
            }
        }

        sb.append("<tr><td>system_cpu_percent</td><td>host=\"system\"</td><td class='val'>")
          .append(String.format(Locale.US, "%.2f%%", cpuPercent())).append("</td><td>gauge</td></tr>");
        sb.append("<tr><td>system_memory_used_percent</td><td>host=\"system\"</td><td class='val'>")
          .append(String.format(Locale.US, "%.2f%%", memPercent())).append("</td><td>gauge</td></tr>");

        sb.append("</tbody></table></div>");
        sb.append("</body></html>");
        return sb.toString();
    }

    // --- JSON API Endpoints ---

    static String jsonSites() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"sites\":[");
        int i = 0;
        int total = statuses.size();
        for (Status s : statuses.values()) {
            sb.append("{")
              .append("\"url\":\"").append(escapeJson(s.url)).append("\",")
              .append("\"name\":\"").append(escapeJson(s.name)).append("\",")
              .append("\"up\":").append(s.up).append(",")
              .append("\"code\":").append(s.code).append(",")
              .append("\"ms\":").append(s.ms).append(",")
              .append("\"uptimePercent\":").append(String.format(Locale.US, "%.1f", s.stats.uptimePercent())).append(",")
              .append("\"avgMs\":").append(s.stats.avgMs()).append(",")
              .append("\"minMs\":").append(s.stats.minMs()).append(",")
              .append("\"maxMs\":").append(s.stats.maxResponseTimeMs).append(",")
              .append("\"sslDays\":").append(s.sslDaysRemaining == null ? "null" : s.sslDaysRemaining).append(",")
              .append("\"checkedAt\":\"").append(escapeJson(s.checkedAt != null ? s.checkedAt : "Pending")).append("\",")
              .append("\"error\":").append(s.error == null ? "null" : "\"" + escapeJson(s.error) + "\"").append(",")
              .append("\"history\":[");
            for (int h = 0; h < s.history.size(); h++) {
                Point p = s.history.get(h);
                sb.append("{\"ms\":").append(p.ms).append(",\"time\":\"").append(escapeJson(p.time)).append("\",\"up\":").append(p.up).append("}");
                if (h < s.history.size() - 1) sb.append(",");
            }
            sb.append("]}");
            if (++i < total) sb.append(",");
        }
        sb.append("],\"cpu\":").append(String.format(Locale.US, "%.1f", cpuPercent()))
          .append(",\"memory\":").append(String.format(Locale.US, "%.1f", memPercent()))
          .append("}");
        return sb.toString();
    }

    static String jsonAlerts() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"alerts\":[");
        for (int i = 0; i < alerts.size(); i++) {
            sb.append("\"").append(escapeJson(alerts.get(i))).append("\"");
            if (i < alerts.size() - 1) sb.append(",");
        }
        sb.append("]}");
        return sb.toString();
    }

    // --- Interactive Modern Web Dashboard ---

    static String dashboard() {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
          .append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
          .append("<title>WebPulse - Website Monitor</title>")
          .append("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
          .append("<style>")
          .append(":root {")
          .append("  --bg-primary: #0f172a; --bg-card: #1e293b; --bg-hover: #243248; --border: #334155;")
          .append("  --text-main: #f8fafc; --text-muted: #94a3b8; --input-bg: #0f172a; --accent: #38bdf8;")
          .append("}")
          .append("body.light-theme {")
          .append("  --bg-primary: #f8fafc; --bg-card: #ffffff; --bg-hover: #f1f5f9; --border: #e2e8f0;")
          .append("  --text-main: #0f172a; --text-muted: #64748b; --input-bg: #ffffff; --accent: #0284c7;")
          .append("}")
          .append("* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; transition: background 0.2s, color 0.2s; }")
          .append("body { background: var(--bg-primary); color: var(--text-main); padding: 24px 32px; min-height: 100vh; }")
          .append(".header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); flex-wrap: wrap; gap: 12px; }")
          .append(".header h1 { font-size: 24px; font-weight: 700; display: flex; align-items: center; gap: 10px; color: var(--accent); }")
          .append(".badge-pulse { display: inline-block; width: 10px; height: 10px; background: #22c55e; border-radius: 50%; box-shadow: 0 0 10px #22c55e; animation: pulse 2s infinite; }")
          .append("@keyframes pulse { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); } 70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(34, 197, 94, 0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); } }")
          .append(".nav-btn { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-main); padding: 7px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }")
          .append(".nav-btn:hover { background: var(--bg-hover); }")
          .append(".stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }")
          .append(".stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }")
          .append(".stat-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; margin-bottom: 6px; }")
          .append(".stat-val { font-size: 26px; font-weight: 700; }")
          .append(".stat-val.up { color: #4ade80; }")
          .append(".stat-val.down { color: #f87171; }")
          .append(".chart-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 24px; }")
          .append(".chart-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }")
          .append(".chart-header h2 { font-size: 16px; font-weight: 600; color: var(--text-main); }")
          .append(".chart-container { position: relative; height: 220px; width: 100%; }")
          .append(".add-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 24px; }")
          .append(".add-card h2 { font-size: 16px; font-weight: 600; margin-bottom: 14px; color: var(--text-main); }")
          .append(".add-form { display: flex; gap: 12px; flex-wrap: wrap; }")
          .append(".add-form input { background: var(--input-bg); border: 1px solid var(--border); color: var(--text-main); padding: 10px 14px; border-radius: 6px; font-size: 14px; outline: none; }")
          .append(".add-form input:focus { border-color: var(--accent); }")
          .append(".add-form input[name='url'] { flex: 2; min-width: 260px; }")
          .append(".add-form input[name='name'] { flex: 1.2; min-width: 180px; }")
          .append(".btn { padding: 10px 20px; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; border: none; }")
          .append(".btn-primary { background: #0284c7; color: #fff; }")
          .append(".btn-primary:hover { background: #0369a1; }")
          .append(".btn-danger { background: #dc2626; color: #fff; padding: 5px 12px; font-size: 12px; border-radius: 4px; border: none; cursor: pointer; }")
          .append(".btn-danger:hover { background: #b91c1c; }")
          .append(".table-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; margin-bottom: 24px; }")
          .append("table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }")
          .append("th { background: var(--bg-primary); padding: 14px 18px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; border-bottom: 1px solid var(--border); }")
          .append("td { padding: 14px 18px; border-bottom: 1px solid var(--border); vertical-align: middle; }")
          .append("tr:hover { background: var(--bg-hover); }")
          .append(".site-name { font-weight: 600; font-size: 15px; }")
          .append(".site-url { font-size: 12px; color: var(--accent); text-decoration: none; word-break: break-all; }")
          .append(".site-url:hover { text-decoration: underline; }")
          .append(".badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; }")
          .append(".badge.up { background: #064e3b; color: #4ade80; border: 1px solid #059669; }")
          .append(".badge.down { background: #7f1d1d; color: #f87171; border: 1px solid #dc2626; }")
          .append(".ssl-badge { font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: 600; }")
          .append(".ssl-good { background: #064e3b; color: #4ade80; }")
          .append(".ssl-warn { background: #78350f; color: #fde047; }")
          .append(".ssl-none { background: var(--bg-primary); color: var(--text-muted); }")
          .append(".latency-pill { font-family: monospace; font-size: 13px; font-weight: 600; }")
          .append(".alerts-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }")
          .append(".alerts-card h2 { font-size: 16px; margin-bottom: 14px; color: var(--text-main); }")
          .append(".alert-item { font-family: monospace; font-size: 13px; padding: 8px 12px; border-radius: 6px; margin-bottom: 6px; background: var(--bg-primary); border-left: 4px solid var(--accent); }")
          .append(".alert-item.DOWN { border-left-color: #ef4444; color: #fca5a5; }")
          .append(".alert-item.RECOVERED { border-left-color: #22c55e; color: #86efac; }")
          .append("</style></head><body>");

        // Header Navigation
        sb.append("<div class='header'>")
          .append("<h1><span class='badge-pulse'></span> WebPulse Monitor</h1>")
          .append("<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>")
          .append("<a href='/metrics' class='nav-btn'>📈 Prometheus Metrics</a>")
          .append("<button class='nav-btn' id='themeBtn' onclick='toggleTheme();'>🌙 Dark</button>")
          .append("</div></div>");

        // Top Stats Cards
        sb.append("<div class='stats-grid'>")
          .append("<div class='stat-card'><div class='stat-title'>Total Monitors</div><div id='statTotal' class='stat-val'>0</div></div>")
          .append("<div class='stat-card'><div class='stat-title'>Online</div><div id='statUp' class='stat-val up'>0</div></div>")
          .append("<div class='stat-card'><div class='stat-title'>Offline</div><div id='statDown' class='stat-val down'>0</div></div>")
          .append("<div class='stat-card'><div class='stat-title'>Avg Latency</div><div id='statLatency' class='stat-val'>0 ms</div></div>")
          .append("<div class='stat-card'><div class='stat-title'>System Health</div><div id='statSystem' class='stat-val' style='font-size:20px;'>CPU: 0% | RAM: 0%</div></div>")
          .append("</div>");

        // Response Time Chart Card
        sb.append("<div class='chart-card'>")
          .append("<div class='chart-header'>")
          .append("<h2>📈 Live Response Time Latency (ms)</h2>")
          .append("<span style='font-size:12px;color:var(--text-muted);'>Auto-refreshes every 5s</span>")
          .append("</div>")
          .append("<div class='chart-container'><canvas id='latencyChart'></canvas></div>")
          .append("</div>");

        // Add Website Form
        sb.append("<div class='add-card'>")
          .append("<h2>➕ Add Website to Monitor</h2>")
          .append("<div id='formAlert' style='display:none;padding:10px 14px;border-radius:6px;margin-bottom:12px;font-size:14px;'></div>")
          .append("<form class='add-form' id='addForm' onsubmit='handleAddSite(event);'>")
          .append("<input type='text' id='siteUrl' name='url' placeholder='URL (e.g. https://example.com or example.com)' required />")
          .append("<input type='text' id='siteName' name='name' placeholder='Friendly Name (optional, defaults to URL)' />")
          .append("<button type='submit' id='addBtn' class='btn btn-primary'>Add Monitor</button>")
          .append("</form></div>");

        // Sites Table
        sb.append("<div class='table-card'><table>")
          .append("<thead><tr>")
          .append("<th>Site & URL</th>")
          .append("<th>Status</th>")
          .append("<th>HTTP Code</th>")
          .append("<th>Latency (min/avg/max)</th>")
          .append("<th>Uptime %</th>")
          .append("<th>SSL Expiry</th>")
          .append("<th>Last Checked</th>")
          .append("<th>Action</th>")
          .append("</tr></thead><tbody id='sitesTableBody'>")
          .append("<tr><td colspan='8' style='text-align:center;padding:30px;color:var(--text-muted);'>Loading monitors...</td></tr>")
          .append("</tbody></table></div>");

        // Recent Alerts
        sb.append("<div class='alerts-card'>")
          .append("<h2>🔔 Recent Alerts & Incidents</h2>")
          .append("<div id='alertsContainer'><p style='color:var(--text-muted);font-size:13px;'>No alerts recorded yet.</p></div>")
          .append("</div>");

        // Client JavaScript
        sb.append("<script>")
          .append("let chart = null;\n")
          .append("const colors = ['#38bdf8', '#34d399', '#f43f5e', '#fbbf24', '#a855f7', '#ec4899', '#06b6d4'];\n")

          // Theme switcher
          .append("if (localStorage.getItem('theme') === 'light') { document.body.classList.add('light-theme'); updateThemeBtn(); }\n")
          .append("function toggleTheme() { document.body.classList.toggle('light-theme'); localStorage.setItem('theme', document.body.classList.contains('light-theme') ? 'light' : 'dark'); updateThemeBtn(); if (chart) chart.update(); }\n")
          .append("function updateThemeBtn() { document.getElementById('themeBtn').innerText = document.body.classList.contains('light-theme') ? '☀️ Light' : '🌙 Dark'; }\n")

          // Add site form handler
          .append("async function handleAddSite(e) {\n")
          .append("  e.preventDefault();\n")
          .append("  const alertEl = document.getElementById('formAlert');\n")
          .append("  const btn = document.getElementById('addBtn');\n")
          .append("  const urlInput = document.getElementById('siteUrl');\n")
          .append("  const nameInput = document.getElementById('siteName');\n")
          .append("  const rawUrl = urlInput.value.trim();\n")
          .append("  if (!rawUrl) return;\n")
          .append("  btn.disabled = true; btn.innerText = 'Adding...';\n")
          .append("  alertEl.style.display = 'none';\n")
          .append("  try {\n")
          .append("    const res = await fetch('/api/sites', {\n")
          .append("      method: 'POST',\n")
          .append("      headers: { 'Content-Type': 'application/json' },\n")
          .append("      body: JSON.stringify({ url: rawUrl, name: nameInput.value.trim(), interval: 10 })\n")
          .append("    });\n")
          .append("    const data = await res.json();\n")
          .append("    if (data.status === 'ok') {\n")
          .append("      alertEl.style.display = 'block'; alertEl.style.background = '#064e3b'; alertEl.style.color = '#86efac'; alertEl.style.border = '1px solid #059669';\n")
          .append("      alertEl.innerText = '✅ Successfully added ' + data.url + '! Initializing check...';\n")
          .append("      urlInput.value = ''; nameInput.value = '';\n")
          .append("      setTimeout(() => { alertEl.style.display = 'none'; }, 4000);\n")
          .append("      refreshData();\n")
          .append("    } else {\n")
          .append("      alertEl.style.display = 'block'; alertEl.style.background = '#7f1d1d'; alertEl.style.color = '#fca5a5'; alertEl.style.border = '1px solid #dc2626';\n")
          .append("      alertEl.innerText = '❌ ' + (data.message || 'Failed to add website.');\n")
          .append("    }\n")
          .append("  } catch(err) {\n")
          .append("    alertEl.style.display = 'block'; alertEl.style.background = '#7f1d1d'; alertEl.style.color = '#fca5a5'; alertEl.style.border = '1px solid #dc2626';\n")
          .append("    alertEl.innerText = '❌ Error: ' + err.message;\n")
          .append("  } finally { btn.disabled = false; btn.innerText = 'Add Monitor'; }\n")
          .append("}\n")

          // Delete site handler
          .append("async function deleteSite(url) {\n")
          .append("  if (!confirm('Stop monitoring ' + url + '?')) return;\n")
          .append("  try {\n")
          .append("    await fetch('/api/sites/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url }) });\n")
          .append("    refreshData();\n")
          .append("  } catch(err) { alert('Delete failed: ' + err.message); }\n")
          .append("}\n")

          .append("function escapeHtml(s) {\n")
          .append("  if (!s) return '';\n")
          .append("  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n")
          .append("}\n")

          // Render Chart
          .append("function updateChart(sites) {\n")
          .append("  if (typeof Chart === 'undefined') return;\n")
          .append("  const ctx = document.getElementById('latencyChart').getContext('2d');\n")
          .append("  const datasets = [];\n")
          .append("  let labels = [];\n")
          .append("  sites.forEach((s, idx) => {\n")
          .append("    const dataPoints = (s.history || []).map(p => p.ms);\n")
          .append("    const timeLabels = (s.history || []).map(p => p.time);\n")
          .append("    if (timeLabels.length > labels.length) labels = timeLabels;\n")
          .append("    datasets.push({\n")
          .append("      label: s.name,\n")
          .append("      data: dataPoints,\n")
          .append("      borderColor: colors[idx % colors.length],\n")
          .append("      backgroundColor: 'transparent',\n")
          .append("      tension: 0.3,\n")
          .append("      borderWidth: 2,\n")
          .append("      pointRadius: 3\n")
          .append("    });\n")
          .append("  });\n")
          .append("  const isLight = document.body.classList.contains('light-theme');\n")
          .append("  const gridColor = isLight ? '#e2e8f0' : '#334155';\n")
          .append("  const textColor = isLight ? '#64748b' : '#94a3b8';\n")
          .append("  if (!chart) {\n")
          .append("    chart = new Chart(ctx, {\n")
          .append("      type: 'line',\n")
          .append("      data: { labels, datasets },\n")
          .append("      options: {\n")
          .append("        responsive: true,\n")
          .append("        maintainAspectRatio: false,\n")
          .append("        plugins: { legend: { labels: { color: textColor } } },\n")
          .append("        scales: {\n")
          .append("          x: { grid: { color: gridColor }, ticks: { color: textColor } },\n")
          .append("          y: { grid: { color: gridColor }, ticks: { color: textColor }, beginAtZero: true }\n")
          .append("        }\n")
          .append("      }\n")
          .append("    });\n")
          .append("  } else {\n")
          .append("    chart.data.labels = labels;\n")
          .append("    chart.data.datasets = datasets;\n")
          .append("    chart.options.scales.x.grid.color = gridColor;\n")
          .append("    chart.options.scales.y.grid.color = gridColor;\n")
          .append("    chart.options.scales.x.ticks.color = textColor;\n")
          .append("    chart.options.scales.y.ticks.color = textColor;\n")
          .append("    chart.options.plugins.legend.labels.color = textColor;\n")
          .append("    chart.update();\n")
          .append("  }\n")
          .append("}\n")

          // Refresh data polling
          .append("async function refreshData() {\n")
          .append("  try {\n")
          .append("    const res = await fetch('/api/sites');\n")
          .append("    if (!res.ok) return;\n")
          .append("    const data = await res.json();\n")
          .append("    const sites = data.sites || [];\n")
          .append("    const total = sites.length;\n")
          .append("    const upCount = sites.filter(s => s.up).length;\n")
          .append("    const downCount = total - upCount;\n")
          .append("    const upSites = sites.filter(s => s.up);\n")
          .append("    const avgLat = upSites.length > 0 ? (upSites.reduce((a, b) => a + b.ms, 0) / upSites.length).toFixed(0) + ' ms' : '0 ms';\n")
          .append("    document.getElementById('statTotal').innerText = total;\n")
          .append("    document.getElementById('statUp').innerText = upCount;\n")
          .append("    document.getElementById('statDown').innerText = downCount;\n")
          .append("    document.getElementById('statLatency').innerText = avgLat;\n")
          .append("    document.getElementById('statSystem').innerText = 'CPU: ' + data.cpu + '% | RAM: ' + data.memory + '%';\n")

          .append("    const tbody = document.getElementById('sitesTableBody');\n")
          .append("    if (sites.length === 0) {\n")
          .append("      tbody.innerHTML = '<tr><td colspan=\"8\" style=\"text-align:center;padding:30px;color:var(--text-muted);\">No websites configured yet. Use the form above to add one.</td></tr>';\n")
          .append("    } else {\n")
          .append("      let rows = '';\n")
          .append("      for (const s of sites) {\n")
          .append("        const statusBadge = s.up ? '<span class=\"badge up\">● ONLINE</span>' : '<span class=\"badge down\">■ OFFLINE</span>';\n")
          .append("        const codeVal = s.code > 0 ? s.code : (s.error ? escapeHtml(s.error) : 'N/A');\n")
          .append("        let sslHtml = '<span class=\"ssl-badge ssl-none\">HTTP only</span>';\n")
          .append("        if (s.sslDays !== null && s.sslDays !== undefined) {\n")
          .append("          const sslClass = s.sslDays < 15 ? 'ssl-warn' : 'ssl-good';\n")
          .append("          sslHtml = '<span class=\"ssl-badge ' + sslClass + '\">' + s.sslDays + ' days</span>';\n")
          .append("        } else if (s.url.startsWith('https://')) {\n")
          .append("          sslHtml = '<span class=\"ssl-badge ssl-none\">Checking...</span>';\n")
          .append("        }\n")
          .append("        const uptimeColor = s.uptimePercent >= 99.0 ? '#4ade80' : '#fde047';\n")
          .append("        rows += '<tr>' +\n")
          .append("          '<td><div><div class=\"site-name\">' + escapeHtml(s.name) + '</div><a class=\"site-url\" href=\"' + escapeHtml(s.url) + '\" target=\"_blank\">' + escapeHtml(s.url) + '</a></div></td>' +\n")
          .append("          '<td>' + statusBadge + '</td>' +\n")
          .append("          '<td>' + codeVal + '</td>' +\n")
          .append("          '<td><span class=\"latency-pill\">' + s.ms + ' ms</span><br><span style=\"font-size:11px;color:var(--text-muted);\">min: ' + s.minMs + ' / avg: ' + s.avgMs + ' / max: ' + s.maxMs + ' ms</span></td>' +\n")
          .append("          '<td><b style=\"color:' + uptimeColor + ';\">' + s.uptimePercent + '%</b></td>' +\n")
          .append("          '<td>' + sslHtml + '</td>' +\n")
          .append("          '<td style=\"color:var(--text-muted);font-size:12px;\">' + escapeHtml(s.checkedAt) + '</td>' +\n")
          .append("          '<td><button type=\"button\" class=\"btn-danger\" onclick=\"deleteSite(\\'' + escapeHtml(s.url) + '\\');\">Delete</button></td>' +\n")
          .append("          '</tr>';\n")
          .append("      }\n")
          .append("      tbody.innerHTML = rows;\n")
          .append("    }\n")
          .append("    updateChart(sites);\n")

          // Update alerts
          .append("    const alertsRes = await fetch('/api/alerts');\n")
          .append("    if (alertsRes.ok) {\n")
          .append("      const aData = await alertsRes.json();\n")
          .append("      const aContainer = document.getElementById('alertsContainer');\n")
          .append("      if (!aData.alerts || aData.alerts.length === 0) {\n")
          .append("        aContainer.innerHTML = '<p style=\"color:var(--text-muted);font-size:13px;\">No downtime alerts recorded yet. All systems operational.</p>';\n")
          .append("      } else {\n")
          .append("        let aHtml = '';\n")
          .append("        for (const a of aData.alerts) {\n")
          .append("          const aType = a.includes('DOWN') ? 'DOWN' : (a.includes('RECOVERED') ? 'RECOVERED' : '');\n")
          .append("          aHtml += '<div class=\"alert-item ' + aType + '\">' + escapeHtml(a) + '</div>';\n")
          .append("        }\n")
          .append("        aContainer.innerHTML = aHtml;\n")
          .append("      }\n")
          .append("    }\n")
          .append("  } catch(err) {}\n")
          .append("}\n")
          .append("refreshData();\n")
          .append("setInterval(refreshData, 5000);\n")
          .append("</script>");

        sb.append("</body></html>");
        return sb.toString();
    }

    // --- HTTP Server & Dispatcher ---

    public static void main(String[] args) throws Exception {
        List<String> sites = args.length > 0 ? Arrays.asList(args) : List.of(
                "https://www.google.com",
                "https://github.com",
                "https://this-site-does-not-exist-12345.com"
        );
        for (String site : sites) {
            registerSite(site, site, 10);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // Web Dashboard
        server.createContext("/", ex -> {
            if ("/".equals(ex.getRequestURI().getPath())) {
                send(ex, dashboard(), "text/html");
            } else {
                sendNotFound(ex);
            }
        });

        // Prometheus Metrics: HTML inspector for humans, raw 0.0.4 text for scrapers
        server.createContext("/metrics", ex -> {
            String accept = ex.getRequestHeaders().getFirst("Accept");
            String query = ex.getRequestURI().getQuery();
            boolean wantsRaw = query != null && query.contains("format=raw");

            if (!wantsRaw && accept != null && accept.contains("text/html")) {
                send(ex, metricsHtml(), "text/html");
            } else {
                send(ex, metrics(), "text/plain; version=0.0.4");
            }
        });

        // REST API: Sites List & Add
        server.createContext("/api/sites", ex -> {
            String method = ex.getRequestMethod().toUpperCase();
            if ("GET".equals(method)) {
                send(ex, jsonSites(), "application/json");
            } else if ("POST".equals(method)) {
                handleCreateSite(ex);
            } else {
                ex.sendResponseHeaders(405, -1);
                ex.close();
            }
        });

        // REST API: Delete Site
        server.createContext("/api/sites/delete", ex -> {
            if ("POST".equals(ex.getRequestMethod().toUpperCase())) {
                handleDeleteSite(ex);
            } else {
                ex.sendResponseHeaders(405, -1);
                ex.close();
            }
        });

        // REST API: Alerts
        server.createContext("/api/alerts", ex -> send(ex, jsonAlerts(), "application/json"));

        server.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down monitor...");
            scheduler.shutdown();
            server.stop(0);
        }));

        System.out.println("WebPulse Monitor running with " + statuses.size() + " sites.");
        System.out.println("Dashboard: http://localhost:8080");
        System.out.println("Metrics:   http://localhost:8080/metrics");
    }

    static void handleCreateSite(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = parseFormOrJson(body);

        String url = params.get("url");
        String name = params.get("name");
        int interval = 10;
        try {
            if (params.containsKey("interval")) interval = Integer.parseInt(params.get("interval"));
        } catch (Exception ignored) {}

        String error = registerSite(url, name, interval);

        String contentType = ex.getRequestHeaders().getFirst("Content-Type");
        String accept = ex.getRequestHeaders().getFirst("Accept");
        boolean isBrowserForm = (contentType != null && contentType.contains("application/x-www-form-urlencoded"))
                || (accept != null && accept.contains("text/html"));

        if (isBrowserForm) {
            String host = ex.getRequestHeaders().getFirst("Host");
            String redirectUri = host != null ? "http://" + host + "/" : "/";
            ex.getResponseHeaders().set("Location", redirectUri);
            ex.sendResponseHeaders(303, -1);
            ex.close();
        } else {
            if (error == null) {
                send(ex, "{\"status\":\"ok\",\"url\":\"" + escapeJson(url) + "\"}", "application/json");
            } else {
                send(ex, "{\"status\":\"error\",\"message\":\"" + escapeJson(error) + "\"}", "application/json");
            }
        }
    }

    static void handleDeleteSite(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = parseFormOrJson(body);

        String url = params.get("url");
        if (url != null) {
            unregisterSite(url.trim());
        }

        String contentType = ex.getRequestHeaders().getFirst("Content-Type");
        String accept = ex.getRequestHeaders().getFirst("Accept");
        boolean isBrowserForm = (contentType != null && contentType.contains("application/x-www-form-urlencoded"))
                || (accept != null && accept.contains("text/html"));

        if (isBrowserForm) {
            String host = ex.getRequestHeaders().getFirst("Host");
            String redirectUri = host != null ? "http://" + host + "/" : "/";
            ex.getResponseHeaders().set("Location", redirectUri);
            ex.sendResponseHeaders(303, -1);
            ex.close();
        } else {
            send(ex, "{\"status\":\"deleted\",\"url\":\"" + escapeJson(url) + "\"}", "application/json");
        }
    }

    static Map<String, String> parseFormOrJson(String body) {
        Map<String, String> map = new HashMap<>();
        if (body == null || body.isBlank()) return map;
        String trimmed = body.trim();

        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            Pattern p = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"([^\"]*)\"|([0-9]+)|true|false|null)");
            Matcher m = p.matcher(trimmed);
            while (m.find()) {
                String key = m.group(1);
                String val = m.group(3) != null ? m.group(3) : m.group(2);
                if (val != null) {
                    map.put(key, val.replace("\\/", "/"));
                }
            }
            return map;
        }

        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String k = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8).trim();
                String v = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8).trim();
                map.put(k, v);
            }
        }
        return map;
    }

    static void send(HttpExchange ex, String body, String type) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
        ex.sendResponseHeaders(200, b.length);
        try (var out = ex.getResponseBody()) {
            out.write(b);
        } finally {
            ex.close();
        }
    }

    static void sendNotFound(HttpExchange ex) throws IOException {
        byte[] b = "404 Not Found".getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(404, b.length);
        try (var out = ex.getResponseBody()) {
            out.write(b);
        } finally {
            ex.close();
        }
    }
}
