# 🌐 WebPulse - Real-Time Website & Service Health Monitor

![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)
![Prometheus](https://img.shields.io/badge/Prometheus-Scraping-red?logo=prometheus)
![Grafana](https://img.shields.io/badge/Grafana-Monitoring-F46800?logo=grafana)
![Jenkins](https://img.shields.io/badge/Jenkins-CI%2FCD-D24939?logo=jenkins)

**WebPulse** is a lightweight, resilient website uptime and latency monitoring solution built with **Java 17**. It features an interactive, modern web dashboard, automated background health checks, SSL certificate expiration tracking, grouped Prometheus metrics exposition, Discord/Slack alerting, and a complete Docker Compose observability stack with Prometheus and Grafana.

---

## 🚀 Key Features

- 📊 **Real-Time Latency History Chart**: Live interactive line chart powered by [Chart.js](https://www.chartjs.org/) tracking latency trends across all monitored endpoints without page refreshes.
- ⚡ **Dynamic Site Management**: Add and delete websites on-the-fly directly from the browser UI with instant asynchronous updates.
- 🔒 **SSL Certificate Expiration Tracking**: Automatically performs TLS handshakes to calculate and display the exact days remaining until SSL certificates expire.
- 📈 **Uptime & Latency Analytics**: Continuously tracks overall uptime percentage along with Minimum, Average, and Maximum latency per endpoint.
- 🌓 **Dark / Light Mode**: Beautiful theme toggle with instant CSS variable switching and local storage persistence.
- 🚨 **Multi-Channel Alerting**: Built-in webhook dispatcher that automatically sends downtime and recovery alerts to Discord or Slack.
- 🔭 **Dual-Mode Prometheus Metrics (`/metrics`)**:
  - Serves strictly formatted Prometheus 0.0.4 metric families (`website_up`, `website_response_ms`) to scrapers.
  - Serves a rich, styled in-browser Metrics Inspector for human visitors.
- 🐳 **Complete Docker Stack**: Pre-configured `docker-compose.yml` linking the Website Monitor, Prometheus server, and Grafana.
- ⚙️ **CI/CD Ready**: Includes a `Jenkinsfile` for automated Maven packaging and Docker image building.

---

## 🏛️ Architecture Overview

```
                            ┌────────────────────────────────────────┐
                            │          Monitored Targets             │
                            │  (https://google.com, github.com, etc) │
                            └───────────────────▲────────────────────┘
                                                │ Periodic Health & SSL Checks
                                                │ (every 10s)
                                                ▼
┌──────────────────────┐    Scrapes Metrics   ┌────────────────────────────────────────┐   Alert Webhooks   ┌──────────────────┐
│  Prometheus Server   │◄─────────────────────│    WebPulse Java Monitor (:8080)       │───────────────────►│  Discord / Slack │
│       (:9090)        │    (/metrics)        │  - Live Latency Chart (Chart.js)       │                    │     Webhooks     │
└──────────┬───────────┘                      │  - Add / Delete Site Management        │                    └──────────────────┘
           │                                  │  - SSL Expiration Calculation          │
           ▼ Data Source                      │  - Uptime % & Latency Stats            │
┌──────────────────────┐                      └───────────────────▲────────────────────┘
│  Grafana Dashboard   │                                          │
│       (:3000)        │                                          │ User Browser Access
└──────────────────────┘                                          ▼
                                                     [http://localhost:8080]
```

---

## 📂 Project Structure

```
.
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── monitor/
│                   └── Monitor.java     # Complete standalone Java 17 monitor & web server
├── Dockerfile                           # Multi-stage build (Maven -> Eclipse Temurin JRE)
├── docker-compose.yml                   # Service orchestration (Monitor, Prometheus, Grafana)
├── Jenkinsfile                          # CI/CD pipeline definition
├── pom.xml                              # Maven build configuration
├── prometheus.yml                       # Prometheus scrape target configuration
├── .gitignore                           # Git ignore rules for build artifacts
└── README.md                            # Project documentation
```

---

## 🚦 Quick Start

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (running with WSL 2 backend on Windows)
- *(Optional for local runs)*: Java 17+ and Maven 3.8+

### 2. Clone the Repository
```bash
git clone https://github.com/KUSHALI0902/Website-monitor.git
cd Website-monitor
```

### 3. Run with Docker Compose
Start the entire monitoring stack with a single command:
```bash
docker compose up --build -d
```

### 4. Access the Stack Services
| Service | URL | Default Credentials | Description |
| :--- | :--- | :--- | :--- |
| **WebPulse Dashboard** | [http://localhost:8080](http://localhost:8080) | *None* | Interactive monitor dashboard & controls |
| **Metrics Inspector** | [http://localhost:8080/metrics](http://localhost:8080/metrics) | *None* | Live Prometheus metrics exposition |
| **Prometheus Server** | [http://localhost:9090](http://localhost:9090) | *None* | Metric scraping & time-series database |
| **Grafana Dashboard** | [http://localhost:3000](http://localhost:3000) | `admin` / `admin` | Advanced metric visualizations & graphs |

---

## 💻 Running Without Docker (Native Java)

If you wish to compile and run the monitor locally without containers:

```bash
# Package the JAR
mvn clean package

# Run the application
java -jar target/website-monitor-1.0.jar
```

The dashboard will be available at `http://localhost:8080`.

---

## ⚙️ Configuration & Environment Variables

You can customize the monitor behavior using the following environment variables (set in shell or in `docker-compose.yml`):

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | Port on which the HTTP server listens |
| `CHECK_INTERVAL_SECONDS` | `10` | Interval between website health probes |
| `WEBHOOK_URL` | *(None)* | Webhook URL for sending downtime/recovery notifications to Discord or Slack |

### Example Webhook Configuration in `docker-compose.yml`:
```yaml
  website-monitor:
    build: .
    environment:
      - PORT=8080
      - CHECK_INTERVAL_SECONDS=10
      - WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_URL
```

---

## 🔄 CI/CD Pipeline (Jenkins)

The included [Jenkinsfile](Jenkinsfile) automates the build and deployment process:
1. **Build Stage**: Executes `mvn -B clean package` to compile and produce the executable JAR.
2. **Docker Stage**: Executes `docker build -t website-monitor .` to generate a lightweight, production-ready container image.

---

## 📊 Prometheus Metrics Details

WebPulse exposes standard metrics under the `/metrics` path:
- `website_up{name="...", url="..."}`: `1.0` when the site is reachable (HTTP 2xx/3xx), `0.0` when unreachable or returning errors.
- `website_response_ms{name="...", url="..."}`: Round-trip response time in milliseconds for the latest check.

---

## 📄 License
This project is open-source and available under the [MIT License](LICENSE).
