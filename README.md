# pcap-analyzer-py-java-war

Find out why HTTP requests are slow, from a packet capture. This is the **Java / WAR port** of [pcap-analyzer-py](https://github.com/maerdogan/pcap-analyzer-py): the same pages, texts and analysis, packaged as a WAR for Tomcat 10.1+, plus a command line jar.

Upload a PCAP and see where the time went: connection setup, network delay, service time, data transfer, or packet loss. It runs on your own server, needs no internet access, and reads captures with tshark.

> [!WARNING]
> Do not expose this application to the internet. It is built for private networks and has had no independent security review. It signs in with one shared HTTP Basic login.

It shows the same pages as the Python version, in Turkish, English, German and Spanish.

Requires Java 17+, Maven 3.9+ to build, tshark 4.0+ (and `mergecap` for captures in parts) on the server.

```bash
mvn package                      # builds target/pcap-analyzer.war
cp target/pcap-analyzer.war $CATALINA_HOME/webapps/
```

Put the settings in `$CATALINA_HOME/bin/setenv.sh`:

```bash
export JAVA_HOME=/path/to/java17
export CATALINA_OPTS="-Xms256m -Xmx1g"
export PCAP_ANALYZER_WORKDIR=/var/lib/pcap-analyzer
export PCAP_ANALYZER_ADMIN_PASSWORD='choose-one'   # required until the password is changed in the app
```

Sign in with HTTP Basic as `admin`. Open `/pcap-analyzer/`.

## Settings

| Variable | Meaning |
|---|---|
| `PCAP_ANALYZER_WORKDIR` | Where analyses are kept. Default: the Java temp folder. |
| `PCAP_ANALYZER_ADMIN_USER`, `PCAP_ANALYZER_ADMIN_PASSWORD` | The shared login. A password set under Preferences replaces the variable. |
| `PCAP_ANALYZER_TSHARK` | Path of tshark. |
| `PCAP_ANALYZER_TTL_DAYS` | Days an analysis is kept. Default 7. |
| `PCAP_ANALYZER_KEEP_CAPTURE` | `0` deletes the capture after the analysis. Packets, graphs, followed streams, services and objects then are not available. |
| `PCAP_ANALYZER_TIMEOUT_S` | Time limit of one tshark run. Default 900. |
| `PCAP_ANALYZER_GEOIP_DIR` | Folder with MaxMind GeoLite2 Country and ASN files. |
| `PCAP_ANALYZER_REQUEST_ID_HEADER` | Header that follows a request through proxies. Default `x-request-id`. |

## REST API

Create a token under Preferences, then send `Authorization: Bearer TOKEN`.

| Call | Result |
|---|---|
| `POST /api/v1/captures` | Upload with the form field `capture`; optional `keylog`, `rsa_key`, `more`, `host_a`, `host_b`, `port`, `start`, `end`, `display_filter`, `decode_as`. Returns `202` and a `job`. |
| `GET /api/v1/jobs/{job}` | `state`: `waiting`, `running`, `done`, `failed`. |
| `GET /api/v1/analyses`, `GET /api/v1/analyses/{id}` | Saved analyses. |
| `GET /api/v1/analyses/{id}/{section}` | `overview`, `urls`, `connections`, `hosts`, `issues`, `slowest`, `statistics`, `services`, `voip`, `check`. |
| `DELETE /api/v1/analyses/{id}` | Deletes an analysis. |

`/check?p95=0.5&error_rate=1&slowest=5` returns `"ok": false` with the limits that were broken, for CI.

## Command line

`mvn package` also builds `target/pcap-analyzer-cli.jar`, which uses the same engine and work folder as the web pages:

```bash
java -jar pcap-analyzer-cli.jar analyze capture.pcap --keylog keys.log --host 10.0.0.5 --port 8080
java -jar pcap-analyzer-cli.jar list
java -jar pcap-analyzer-cli.jar inspect ANALYSIS_ID --src 10.0.0.5 --dst 10.0.0.9 --port 8080
java -jar pcap-analyzer-cli.jar check ANALYSIS_ID --p95 0.5 --error-rate 1    # exit code 2 when a limit is broken
java -jar pcap-analyzer-cli.jar set-password
```

## Large captures

A connection that has closed and stayed quiet for five minutes of capture time is finished and its packets are freed, so memory stays low. A 450 MB capture was analyzed with a 400 MB heap in 19 seconds. The capture is fed to tshark through its standard input, so no copy of it is made.

## Not ported

HTTP/3 requests as rows in the request lists (QUIC connections and their stream counts are shown), the Python `serve` and `hash-password` commands (Tomcat serves the pages, and `set-password` replaces `hash-password`), and the Python version's job queue page (uploads through the web page are analyzed while the request waits; the REST API runs them as jobs).

## Notes

- Verified against tshark's own request counts on real captures, and on synthetic captures with HTTP/2, SMTP, FTP, SIP and RTP. GeoIP lookups and LDAP, Kerberos, SMB2, Kafka, DCERPC, MQTT and AMQP response times follow the Python logic but were not tried on real traffic.
- Texts and explanations are exported from the Python project's knowledge base.


Parts-based reading of captures near 1 GB (the Java version holds one analysis in memory, so give Tomcat enough heap), expert-information views other than the issue list, and the Python command line.
