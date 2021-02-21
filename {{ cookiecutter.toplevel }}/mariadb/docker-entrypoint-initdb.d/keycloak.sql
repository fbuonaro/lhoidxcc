CREATE DATABASE IF NOT EXISTS keycloak;
CREATE USER IF NOT EXISTS '{{ cookiecutter.keycloak_db_user }}'@'%' IDENTIFIED BY '{{ cookiecutter.keycloak_db_password }}';
GRANT ALL PRIVILEGES ON keycloak.* to '{{ cookiecutter.keycloak_db_user }}'@'%';
FLUSH PRIVILEGES;
