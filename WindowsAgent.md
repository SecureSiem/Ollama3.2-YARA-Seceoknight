# Windows 11 endpoint

Perform the following steps to install Python, YARA, and download YARA rules.

1. Download the Python executable installer from the official Python website.

        https://www.python.org/downloads/windows/

2. Run the Python installer once downloaded, and make sure to check the following boxes:

        Install launcher for all users

  Add python.exe to PATH. This places the Python interpreter in the execution path.

3. Download and install the latest Visual C++ Redistributable package.

4. Open PowerShell with administrator privileges to download and extract YARA:

        Invoke-WebRequest -Uri https://github.com/VirusTotal/yara/releases/download/v4.5.1/yara-v4.5.1-2298-win64.zip -OutFile yara-v4.5.1-2298-win64.zip
        Expand-Archive yara-v4.5.1-2298-win64.zip; Remove-Item yara-v4.5.1-2298-win64.zip

5. Create a directory called C:\Program Files (x86)\ossec-agent\active-response\bin\yara\ and copy the YARA executable into it:

        mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'
        cp .\yara-v4.5.1-2298-win64\yara64.exe 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'

6. Download YARA rules using valhallaAPI. Valhalla is a YARA and Sigma rule repository provided by Nextron Systems:

        python -m pip install valhallaAPI
        python -c "from valhallaAPI.valhalla import ValhallaAPI; v = ValhallaAPI(api_key='1111111111111111111111111111111111111111111111111111111111111111'); response = v.get_rules_text(); open('yara_rules.yar', 'w').write(response)"
        mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'
        cp yara_rules.yar 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'
