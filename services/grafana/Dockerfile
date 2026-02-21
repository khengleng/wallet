FROM grafana/grafana:11.1.4

COPY provisioning /etc/grafana/provisioning
COPY dashboards /var/lib/grafana/dashboards
COPY --chmod=755 start-grafana.sh /usr/local/bin/start-grafana.sh

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/start-grafana.sh"]
