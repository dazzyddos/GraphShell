## GraphShell: A Command-Line Tool for Microsoft Graph API Exploration
### Overview
GraphShell is a command-line tool designed for interacting with Microsoft Graph API. It facilitates various operations such as enumerating users, groups, devices, and sending emails. The tool was developed as part of an exploration into device code phishing and Microsoft Graph API functionalities. If you are looking for more functionality, I would recommend exploring [AADInternals](https://github.com/Gerenios/AADInternals) and [TokenTactics](https://github.com/rvrsh3ll/TokenTactics). I am sure there would be some more cool projects but I haven't explored them yet :D

### Features
**Enumerate Users** - List all users in the Azure Active Directory.
**Enumerate Groups** - List all groups in the Azure Active Directory.
**Enumerate Devices** - List all devices in the Azure Active Directory.
**Dump Emails** - Retrieve emails from the authenticated user's mailbox.
**Send Email** - Send an email from the authenticated user's account.
**User Details** - Retrieve details of a specific user.
**Group Members** - Retrieve members of a specific group.
**User's Manager** - Retrieve the manager of a specific user.
**Direct Reports** - Retrieve direct reports of a specific user.
**User Events** - Retrieve calendar events of a specific user.
**User Contacts** - Retrieve contacts of a specific user.
**User Drive Files** - Retrieve files in a user's OneDrive.
**Download File** - Download a file from OneDrive.
**Upload File** - Upload a file to OneDrive.
**Token Permissions** - Print token permissions.
**Token Details** - Print token details.
**Print Access Token** - Print the current access token.
**Refresh Access Token** - Refresh the access token.

#### Installation and Usage
Clone the repository:
```bash
git clone https://github.com/dazzyddos/GraphShell.git
cd GraphShell
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Run the tool:
```bash
python device_code_shell.py
```

Authenticate:
```
The device code needs to be entered at the provided URL i.e., https://microsoft.com/devicelogin
```

![](https://raw.githubusercontent.com/dazzyddos/GraphShell/main/images/sample1.png)

Explore Commands:
```
Once authenticated, you can use various commands to interact with Microsoft Graph API.
```
![](https://raw.githubusercontent.com/dazzyddos/GraphShell/main/images/sample2.png)

