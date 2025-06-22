# bot/teams_handler.py

import os
import re
import json
import time
import requests
import threading
import http.server
import urllib.parse
import socketserver
from dateutil import parser
from datetime import datetime, timezone
from bot.command_parser import CommandParser

class TeamsBot:
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.token_file = "token.json"
        self.token_result = {}
        
        # OAuth2 and bot configuration from environment
        self.tenant_id = os.environ.get("TENANT_ID")
        self.client_id = os.environ.get("CLIENT_ID")
        self.client_secret = os.environ.get("CLIENT_SECRET")
        self.redirect_uri = os.environ.get("REDIRECT_URI")
        self.scope = os.environ.get("API_SCOPE")
        self.chat_id = os.environ.get("CHAT_ID")
        
        # Build auth URLs
        self.auth_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize?"
            f"client_id={self.client_id}&response_type=code&redirect_uri={self.redirect_uri}"
            f"&response_mode=query&scope={urllib.parse.quote(self.scope)}&state=12345"
        )
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        
        # Initialize command parser
        self.command_parser = CommandParser()

    def validate_environment(self):
        """Validate required environment variables"""
        required_vars = {
            "TENANT_ID": self.tenant_id,
            "CLIENT_ID": self.client_id,
            "CLIENT_SECRET": self.client_secret,
            "REDIRECT_URI": self.redirect_uri,
            "API_SCOPE": self.scope,
            "CHAT_ID": self.chat_id
        }

        missing_vars = [var for var, value in required_vars.items() if not value]
        if missing_vars:
            print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
            return False

        print(f"✅ Chat ID configured: {self.chat_id}")
        
        # Check optional environment variables
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_api_key:
            print("⚠️ Warning: GEMINI_API_KEY not set. /ai-check command will not work.")
        
        # Check vCenter credentials
        vc_host = os.environ.get("VC_HOST")
        vc_user = os.environ.get("VC_USERNAME")
        vc_pass = os.environ.get("VC_PASSWORD")
        
        if not all([vc_host, vc_user, vc_pass]):
            print("⚠️ Warning: vCenter credentials not fully configured. /find command will not work.")
        
        return True

    def save_token(self, token_data):
        """Save token data to file"""
        try:
            with open(self.token_file, "w") as f:
                json.dump(token_data, f)
            print("💾 Token saved successfully")
        except Exception as e:
            print(f"❌ Failed to save token: {e}")

    def load_token(self):
        """Load token data from file"""
        try:
            with open(self.token_file, "r") as f:
                token_data = json.load(f)
            print("📂 Token loaded from file")
            return token_data
        except FileNotFoundError:
            print("📂 No existing token file found")
            return None
        except Exception as e:
            print(f"❌ Failed to load token: {e}")
            return None

    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        print("🔁 Exchanging code for token...")
        data = {
            "client_id": self.client_id,
            "scope": self.scope,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
            "client_secret": self.client_secret
        }

        try:
            r = requests.post(self.token_url, data=data, timeout=30)
            r.raise_for_status()
            token_data = r.json()

            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in", 3600)

            if not access_token:
                print("❌ Failed to get access token.")
                print("Response:", token_data)
                return None

            token_data["expires_at"] = int(time.time()) + int(expires_in)
            self.save_token(token_data)
            self.token_result.update(token_data)
            print("✅ Token acquired and saved!")
            return token_data
        
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error during token exchange: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error during token exchange: {e}")
            return None

    def refresh_access_token(self, refresh_token):
        """Refresh the access token using refresh token"""
        print("🔄 Refreshing access token...")
        data = {
            "client_id": self.client_id,
            "scope": self.scope,
            "refresh_token": refresh_token,
            "redirect_uri": self.redirect_uri,
            "grant_type": "refresh_token",
            "client_secret": self.client_secret
        }

        try:
            r = requests.post(self.token_url, data=data, timeout=30)
            r.raise_for_status()
            token_data = r.json()

            access_token = token_data.get("access_token")
            if not access_token:
                print("❌ Failed to refresh token.")
                print("Response:", token_data)
                return None

            expires_in = token_data.get("expires_in", 3600)
            token_data["expires_at"] = int(time.time()) + int(expires_in)
            self.save_token(token_data)
            self.token_result.update(token_data)
            print("✅ Token refreshed and saved!")
            return token_data
        
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error during token refresh: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error during token refresh: {e}")
            return None

    def load_or_refresh_token(self):
        """Load existing token or start auth flow"""
        token_data = self.load_token()

        if not token_data:
            print("🔐 No existing token, starting auth flow...")
            return self.start_auth_flow()

        # Check if token is still valid (with 5 minute buffer)
        if time.time() < (token_data.get("expires_at", 0) - 300):
            print("✅ Using cached access token")
            self.token_result.update(token_data)
            return token_data["access_token"]

        print("🔄 Token expired, attempting refresh...")
        refresh_result = self.refresh_access_token(token_data.get("refresh_token"))
        
        if refresh_result:
            return refresh_result.get("access_token")
        else:
            print("❌ Token refresh failed, starting new auth flow...")
            return self.start_auth_flow()

    class CodeHandler(http.server.BaseHTTPRequestHandler):
        def __init__(self, teams_bot_instance, *args, **kwargs):
            self.teams_bot = teams_bot_instance
            super().__init__(*args, **kwargs)

        def do_GET(self):
            try:
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)
                code = params.get("code", [None])[0]
                error = params.get("error", [None])[0]
                
                if error:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(f"Authentication error: {error}".encode())
                    return
                    
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Login successful. You can close this window.")

                if code:
                    thread = threading.Thread(target=self.teams_bot.exchange_code_for_token, args=(code,))
                    thread.start()
                    thread.join()
            except Exception as e:
                print(f"❌ Error in auth handler: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal server error")

        def log_message(self, format, *args):
            # Suppress default HTTP server logging
            pass

    def start_auth_flow(self):
        """Start OAuth2 authentication flow"""
        print("🔗 Open this link in browser to authenticate:")
        print(self.auth_url)
        
        try:
            handler = lambda *args, **kwargs: self.CodeHandler(self, *args, **kwargs)
            with socketserver.TCPServer(("localhost", 8080), handler) as httpd:
                print("🌐 Waiting for authentication on localhost:8080...")
                httpd.handle_request()
            return self.token_result.get("access_token")
        except Exception as e:
            print(f"❌ Failed to start auth server: {e}")
            return None

    def send_message(self, token, chat_id, text):
        """Send message to Microsoft Teams chat"""
        url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        payload = {
            "body": {
                "contentType": "html",
                "content": text
            }
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            print("📨 Send status:", response.status_code)
            
            if response.status_code == 201:
                print("✅ Message sent successfully")
            else:
                print("❌ Send response:", response.text)
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error sending message: {e}")
        except Exception as e:
            print(f"❌ Unexpected error sending message: {e}")

    def process_message(self, msg, access_token, chat_id):
        """Process a single message and respond if needed"""
        try:
            sender = msg.get("from", {}).get("user", {}).get("displayName", "Unknown")
            
            # Skip bot's own messages
            if sender == "Bot" or msg.get("from", {}).get("application"):
                return False
            
            # Strip and sanitize HTML content
            content = ""
            body = msg.get("body")
            if body and isinstance(body, dict):
                content = body.get("content", "")
                content = re.sub(r'<.*?>', '', content).strip()

            if not content:
                return False

            print(f"💬 Message from {sender}: {content}")

            # Process command using command parser
            response = self.command_parser.process_command(content)
            
            if response:
                self.send_message(access_token, chat_id, response)
                return True

            return False

        except Exception as e:
            print(f"❌ Error processing message: {e}")
            return False

    def poll_and_respond(self, access_token, chat_id):
        """Poll for new messages and respond to commands"""
        url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages"
        headers = {"Authorization": f"Bearer {access_token}"}
        last_seen_id = None
        consecutive_errors = 0
        max_consecutive_errors = 5

        print("🔄 Starting message polling...")

        while True:
            try:
                # Make API request with timeout
                r = requests.get(url, headers=headers, timeout=30)
                
                # Handle different HTTP status codes
                if r.status_code == 401:
                    print("❌ Authentication failed. Token may be expired.")
                    time.sleep(10)
                    continue
                elif r.status_code == 403:
                    print("❌ Access forbidden. Check bot permissions.")
                    time.sleep(10)
                    continue
                elif r.status_code != 200:
                    print(f"❌ API request failed with status {r.status_code}: {r.text}")
                    time.sleep(5)
                    continue

                # Parse JSON response
                try:
                    data = r.json()
                    if not isinstance(data, dict):
                        print("❌ Invalid response format - expected JSON object")
                        time.sleep(5)
                        continue
                        
                    messages = data.get("value", [])
                    if not isinstance(messages, list):
                        print("❌ Invalid messages format - expected list")
                        time.sleep(5)
                        continue
                        
                except (json.JSONDecodeError, ValueError) as e:
                    print(f"⚠️ Failed to parse JSON response: {e}")
                    print(f"🔸 Raw response text (first 500 chars): {r.text[:500]}")
                    time.sleep(5)
                    continue

                # Reset error counter on successful request
                consecutive_errors = 0

                # Process messages in reverse order (oldest first)
                processed_count = 0
                for msg in reversed(messages):
                    if not isinstance(msg, dict):
                        continue
                        
                    msg_id = msg.get("id")
                    if not msg_id:
                        continue

                    # Check message timestamp
                    created_time_str = msg.get("createdDateTime")
                    if created_time_str:
                        try:
                            msg_time = parser.isoparse(created_time_str)
                            # Skip messages older than bot start time (with 30 second buffer)
                            if (msg_time - self.start_time).total_seconds() < -30:
                                continue
                        except Exception as e:
                            print(f"⚠️ Failed to parse message timestamp: {e}")
                            continue

                    # Skip already processed messages
                    if last_seen_id and msg_id <= last_seen_id:
                        continue

                    # Process the message
                    if self.process_message(msg, access_token, chat_id):
                        processed_count += 1
                    
                    last_seen_id = msg_id

                if processed_count > 0:
                    print(f"✅ Processed {processed_count} new messages")

                # Wait before next poll
                time.sleep(5)

            except requests.exceptions.Timeout:
                print("⚠️ Request timeout - retrying...")
                consecutive_errors += 1
                time.sleep(5)
                
            except requests.exceptions.ConnectionError:
                print("⚠️ Connection error - retrying...")
                consecutive_errors += 1
                time.sleep(10)
                
            except requests.exceptions.RequestException as e:
                print(f"⚠️ Request error: {e}")
                consecutive_errors += 1
                time.sleep(5)
                
            except Exception as e:
                print(f"⚠️ Unexpected polling error: {e}")
                consecutive_errors += 1
                time.sleep(5)

            # Exit if too many consecutive errors
            if consecutive_errors >= max_consecutive_errors:
                print(f"❌ Too many consecutive errors ({consecutive_errors}). Exiting.")
                break

    def run(self):
        """Main run method for the bot"""
        # Get access token
        access_token = self.load_or_refresh_token()
        if not access_token:
            print("❌ Could not obtain access token.")
            return
        
        print("✅ Authentication successful")
        
        # Start polling
        self.poll_and_respond(access_token, self.chat_id)