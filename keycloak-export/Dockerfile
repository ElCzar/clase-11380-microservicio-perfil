FROM quay.io/keycloak/keycloak:26.3.3-0

# Copy the exported realm configuration with all custom attributes
COPY microservices-ecosystem-realm.json /opt/keycloak/data/import/

# Create import directory and set permissions
USER root
RUN mkdir -p /opt/keycloak/data/import && chown -R keycloak:keycloak /opt/keycloak/data
USER keycloak

# Override default command to include import
CMD ["start-dev", "--import-realm"]