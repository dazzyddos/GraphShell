import requests
import time
import jwt
import cmd
import json
from termcolor import colored

class GraphShell(cmd.Cmd):
    prompt = colored(">> ", "blue")
    intro = "Welcome to the GraphShell! Type ? to list commands"

    def __init__(self, access_token, refresh_token, token_details):
        super().__init__()
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_details = token_details

    def do_enum_users(self, arg):
        """Enumerate users: enum_users"""
        enumerate_users(self.access_token)

    def do_enum_groups(self, arg):
        """Enumerate groups: enum_groups"""
        enumerate_groups(self.access_token)

    def do_enum_devices(self, arg):
        """Enumerate devices: enum_devices"""
        enumerate_devices(self.access_token)

    def do_dump_email(self, arg):
        """Dump emails: dump_email"""
        dump_emails(self.access_token)

    def do_get_user_details(self, arg):
        """Get details of a specific user: get_user_details <user_id>"""
        if not arg:
            print(colored("User ID is required. Usage: get_user_details <user_id>", "red"))
        else:
            get_user_details(self.access_token, arg)

    def do_get_group_members(self, arg):
        """Get members of a specific group: get_group_members <group_id>"""
        if not arg:
            print(colored("Group ID is required. Usage: get_group_members <group_id>", "red"))
        else:
            get_group_members(self.access_token, arg)

    def do_get_user_manager(self, arg):
        """Get the manager of a specific user: get_user_manager <user_id>"""
        if not arg:
            print(colored("User ID is required. Usage: get_user_manager <user_id>", "red"))
        else:
            get_user_manager(self.access_token, arg)

    def do_get_user_direct_reports(self, arg):
        """Get the direct reports of a specific user: get_user_direct_reports <user_id>"""
        if not arg:
            print(colored("User ID is required. Usage: get_user_direct_reports <user_id>", "red"))
        else:
            get_user_direct_reports(self.access_token, arg)

    def do_get_user_events(self, arg):
        """Get calendar events of a specific user: get_user_events <user_id>"""
        if not arg:
            print(colored("User ID is required. Usage: get_user_events <user_id>", "red"))
        else:
            get_user_events(self.access_token, arg)

    def do_get_user_contacts(self, arg):
        """Get contacts of a specific user: get_user_contacts <user_id>"""
        if not arg:
            print(colored("User ID is required. Usage: get_user_contacts <user_id>", "red"))
        else:
            get_user_contacts(self.access_token, arg)

    def do_get_user_drive_files(self, arg):
        """Get files in a user's OneDrive: get_user_drive_files <user_id>"""
        if not arg:
            print(colored("User ID is required. Usage: get_user_drive_files <user_id>", "red"))
        else:
            get_user_drive_files(self.access_token, arg)

    def do_download_file(self, arg):
        """Download a file from OneDrive: download_file <user_id> <item_id> <local_path>"""
        args = arg.split()
        if len(args) != 3:
            print(colored("Usage: download_file <user_id> <item_id> <local_path>", "red"))
        else:
            user_id, item_id, local_path = args
            download_file(self.access_token, user_id, item_id, local_path)

    def do_upload_file(self, arg):
        """Upload a file to OneDrive: upload_file <user_id> <local_path> <drive_path>"""
        args = arg.split()
        if len(args) != 3:
            print(colored("Usage: upload_file <user_id> <local_path> <drive_path>", "red"))
        else:
            user_id, local_path, drive_path = args
            upload_file(self.access_token, user_id, local_path, drive_path)

    def do_send_email(self, arg):
        """Send an email: send_email <recipient_email> <subject> <email_content>"""
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

    def do_token_permissions(self, arg):
        """Print token permissions: token_permissions"""
        permissions = get_permissions(self.access_token)
        print(colored("Token Permissions:", "blue"))
        print(permissions)

    def do_token_details(self, arg):
        """Print token details: token_details"""
        print(colored("Token Details:", "blue"))
        print(json.dumps(self.token_details, indent=4))

    def do_print_access_token(self, arg):
        """Print the current access token: print_access_token"""
        print(colored("Current Access Token:", "blue"))
        print(self.access_token)

    def do_refresh_access_token(self, arg):
        """Refresh the access token: refresh_access_token"""
        new_access_token = refresh_access_token(self.refresh_token)
        if new_access_token:
            self.access_token = new_access_token
            print(colored("[+] Access token refreshed successfully!", "green"))

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
                print(colored(details['error'], "red"))
                
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
        if response.status_code == 201:
            print(colored('[+] File uploaded successfully!', 'green'))
        else:
            print(colored('[!] Something went wrong...', 'red'))
            print(f"Error details: {response.json()}")

# Doesn't work for some reason. All the mails I am sending is not getting delivered
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

def get_group_members(token, group_id):
    msgraph_url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members'
    msgraph_headers = {
        'Authorization': 'Bearer ' + token
    }

    response = requests.get(msgraph_url, headers=msgraph_headers)
    if response.status_code == 200:
        members = response.json().get('value', [])
        print(colored('[+] Group members:', 'green'))
        print(json.dumps(members, indent=4))
    else:
        print(colored('[!] Something went wrong...', 'red'))
        print(f"Error details: {response.json()}")

def main():
    auth_response = get_device_code()
    if auth_response:
        user_code = auth_response['user_code']
        print(f"User code: {user_code}")
        print("Please visit", colored("https://microsoft.com/devicelogin", "blue"), "and enter the user code.")

        auth_result = poll_for_authorization(auth_response)
        if auth_result:
            access_token = auth_result['access_token']
            refresh_token = auth_result['refresh_token']
            token_details = auth_result
            print(colored("Authentication successful!", "green"))
            
            shell = GraphShell(access_token, refresh_token, token_details)
            shell.cmdloop()
        else:
            print(colored("Authentication failed or timed out!", "red"))

if __name__ == "__main__":
    main()
