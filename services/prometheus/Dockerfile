FROM prom/prometheus:v2.54.1

COPY alerts /etc/prometheus/alerts
COPY start-prometheus.sh /usr/local/bin/start-prometheus.sh

RUN chmod +x /usr/local/bin/start-prometheus.sh

EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/start-prometheus.sh"]
