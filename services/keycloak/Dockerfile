FROM quay.io/keycloak/keycloak:26.0

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--http-enabled=true", "--hostname-strict=false", "--proxy-headers=xforwarded"]
