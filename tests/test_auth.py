import os
import uuid
import pytest
import requests
import json
from keycloak import KeycloakAdmin, KeycloakOpenID
from time import sleep


class TestKeycloakAuth:
    @pytest.fixture(scope="session")
    def keycloak_setup(self):
        base_url = os.getenv('KEYCLOAK_URL')
        print(f"Using Keycloak URL: {base_url}")

        # Get admin token first
        admin_token_url = f"{base_url}/realms/master/protocol/openid-connect/token"
        admin_token_data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.getenv('KEYCLOAK_ADMIN', 'admin'),
            "password": os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin')
        }

        print("Getting admin token...")
        admin_token_response = requests.post(admin_token_url, data=admin_token_data)
        if admin_token_response.status_code != 200:
            print(f"Failed to get admin token: {admin_token_response.text}")
            raise Exception("Failed to get admin token")

        admin_token = admin_token_response.json()['access_token']
        print("Got admin token successfully")

        # Initialize admin client
        admin_client = KeycloakAdmin(
            server_url=base_url,
            username=os.getenv('KEYCLOAK_ADMIN', 'admin'),
            password=os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin'),
            realm_name="master",
            verify=True
        )

        # Create test realm
        realm_name = os.getenv('TEST_REALM_NAME')
        try:
            # Delete realm if it exists
            try:
                admin_client.delete_realm(realm_name)
                print(f"Deleted existing realm: {realm_name}")
            except Exception:
                pass

            # Create new realm
            print(f"Creating new realm: {realm_name}")
            admin_client.create_realm(
                payload={
                    "realm": realm_name,
                    "enabled": True,
                    "accessTokenLifespan": 300,
                    "resetPasswordAllowed": True,
                    "verifyEmail": False,
                    "loginWithEmailAllowed": True,
                    "duplicateEmailsAllowed": False,
                    "requiredActions": []  # No required actions by default
                }
            )

            # Create client
            client_id = os.getenv('TEST_CLIENT_ID')
            client_secret = str(uuid.uuid4())

            print(f"Creating client {client_id} in realm {realm_name}")

            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {admin_token}'
            }

            client_data = {
                "clientId": client_id,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": client_secret,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "clientAuthenticatorType": "client-secret",
                "redirectUris": ["*"],
                "webOrigins": ["*"]
            }

            client_url = f"{base_url}/admin/realms/{realm_name}/clients"
            response = requests.post(
                client_url,
                headers=headers,
                json=client_data
            )

            if response.status_code not in [201, 204]:
                print(f"Error creating client. Status: {response.status_code}")
                print(f"Response: {response.text}")
                raise Exception("Failed to create client")

            print("Client created successfully")

            # Get client details
            clients_response = requests.get(
                client_url,
                headers=headers
            )
            clients = clients_response.json()
            created_client = next(c for c in clients if c['clientId'] == client_id)
            print(f"Found client: {json.dumps(created_client, indent=2)}")

            # Create user with complete profile
            username = os.getenv('TEST_USERNAME')
            password = os.getenv('TEST_PASSWORD', 'test-password')

            user_data = {
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "firstName": "Test",
                "lastName": "User",
                "email": "test@example.com",
                "requiredActions": [],
                "credentials": [{
                    "type": "password",
                    "value": password,
                    "temporary": False
                }],
                "attributes": {
                    "locale": ["en"]
                }
            }

            user_url = f"{base_url}/admin/realms/{realm_name}/users"
            response = requests.post(
                user_url,
                headers=headers,
                json=user_data
            )

            if response.status_code not in [201, 204]:
                print(f"Error creating user. Status: {response.status_code}")
                print(f"Response: {response.text}")
                raise Exception("Failed to create user")

            print(f"Created user: {username}")

            # Get user ID
            users_response = requests.get(
                f"{user_url}?username={username}",
                headers=headers
            )
            users = users_response.json()
            if not users:
                raise Exception("Created user not found")

            user_id = users[0]['id']

            # Test direct token request
            token_url = f"{base_url}/realms/{realm_name}/protocol/openid-connect/token"
            token_data = {
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": created_client['secret'],  # Use the secret from the created client
                "username": username,
                "password": password,
                "scope": "openid email profile"
            }

            print(f"\nTesting token endpoint: {token_url}")
            print(f"Token request data: {token_data}")

            token_response = requests.post(token_url, data=token_data)
            print(f"Token response status: {token_response.status_code}")
            print(f"Token response: {token_response.text}")

            if token_response.status_code != 200:
                raise Exception(f"Token test failed: {token_response.text}")

            return {
                "realm_name": realm_name,
                "client_id": client_id,
                "client_secret": created_client['secret']  # Use the secret from the created client
            }

        except Exception as e:
            print(f"Setup failed: {e}")
            raise

    def test_password_grant(self, keycloak_setup):
        print("\nTesting password grant flow with:")
        print(f"Server URL: {os.getenv('KEYCLOAK_URL')}")
        print(f"Realm: {keycloak_setup['realm_name']}")
        print(f"Client ID: {keycloak_setup['client_id']}")
        print(f"Client Secret: {keycloak_setup['client_secret']}")
        print(f"Username: {os.getenv('TEST_USERNAME')}")
        print(f"Password: {os.getenv('TEST_PASSWORD')}")

        keycloak_openid = KeycloakOpenID(
            server_url=os.getenv('KEYCLOAK_URL'),
            client_id=keycloak_setup["client_id"],
            realm_name=keycloak_setup["realm_name"],
            client_secret_key=keycloak_setup["client_secret"]
        )

        token = keycloak_openid.token(
            grant_type="password",
            username=os.getenv('TEST_USERNAME'),
            password=os.getenv('TEST_PASSWORD'),
            scope="openid email profile"
        )

        assert token["access_token"] is not None
        assert token["refresh_token"] is not None
        assert token["token_type"] == "Bearer"

    def test_client_credentials(self, keycloak_setup):
        keycloak_openid = KeycloakOpenID(
            server_url=os.getenv('KEYCLOAK_URL'),
            client_id=keycloak_setup["client_id"],
            realm_name=keycloak_setup["realm_name"],
            client_secret_key=keycloak_setup["client_secret"]
        )

        token = keycloak_openid.token(
            grant_type="client_credentials"
        )

        assert token["access_token"] is not None
        assert token["token_type"] == "Bearer"

    def test_token_refresh(self, keycloak_setup):
        keycloak_openid = KeycloakOpenID(
            server_url=os.getenv('KEYCLOAK_URL'),
            client_id=keycloak_setup["client_id"],
            realm_name=keycloak_setup["realm_name"],
            client_secret_key=keycloak_setup["client_secret"]
        )

        token = keycloak_openid.token(
            grant_type="password",
            username=os.getenv('TEST_USERNAME'),
            password=os.getenv('TEST_PASSWORD'),
            scope="openid email profile"
        )

        refreshed_token = keycloak_openid.refresh_token(
            refresh_token=token["refresh_token"]
        )

        assert refreshed_token["access_token"] is not None
        assert refreshed_token["access_token"] != token["access_token"]
