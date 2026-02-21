FROM quay.io/keycloak/keycloak:26.0

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--http-enabled=true", "--hostname-strict=true", "--proxy-headers=xforwarded"]
