FROM prom/alertmanager:v0.27.0

COPY --chmod=755 start-alertmanager.sh /usr/local/bin/start-alertmanager.sh

EXPOSE 9093

ENTRYPOINT ["/usr/local/bin/start-alertmanager.sh"]
