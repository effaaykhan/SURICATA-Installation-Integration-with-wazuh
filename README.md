# SURICATA-Installation-Integration-with-wazuh
This repository contains the installation and integration guide for suricata with wazuh

# FOR UBUNTU
### ➡️ Install Suricata on Ubuntu 
  ```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
  ```
### ➡️ Download and extract the emerging threats suricata ruleset
  ```bash
 cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
 sudo tar -xvzf emerging.rules.tar.gz && sudo mkdir /etc/suricata/rules && sudo mv rules/*.rules /etc/suricata/rules/
 sudo chmod 640 /etc/suricata/rules/*.rules
 ```
### ➡️Modify Suricata settings in the suricata configuration file
 ```bash
  nano /etc/suricata/suricata.yaml
 ```
### ➡️Add/update the following configurations
  ```bash
   HOME_NET: "<UBUNTU_IP>"
            EXTERNAL_NET: "any"

           default-rule-path: /etc/suricata/rules
           rule-files:
               - "*.rules"

          # Global stats configuration
                 stats:
           enabled: yes

          # Linux high speed capture support
          af-packet:
               - interface: <host/server net-interface>
   ```
 ### ➡️Restart the Suricata Service
 ```bash
    systemctl restart suricata
```

 ### ➡️Add the following configuration to the /var/ossec/etc/ossec.conf file of the wazuh manager (if suricata is installed on agent then configure agent file). This allows wazuh manager/agent to read the Suricata logs file:

  ```bash
    <ossec_config>
        <localfile
            <log_format>json</log_format>
            <location>/var/log/suricata/eve.json</location>
       </localfile>
    </ossec_config>
 ```
 ### ➡️Restart the Wazuh manager/agent to apply the changes
   ```bash
    systemctl restart wazuh-manager
  ```

 -	Wazuh automatically parses data from /var/log/suricata/eve.json & generates related alerts on the Wazuh dashboard.


# FOR WINDOWS
### ➡️ Install Suricata on Windows
- Download and Install ```npcap``` on windows:
  ```
  https://npcap.com/dist/npcap-1.82.exe
  ```
- Download and Install the latest Suricata Installer (current is 7.0.10)
  ```
  https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.10-1-64bit.msi
  ```
- Run the installer and goto ```C:\Program Files\Suricata``` directory
  ```
  cd C:\Program Files\Suricata
  ```
- Now open the ```suricata.yaml``` file
  ```
  notepad suricata.yaml
  ```
- Modify the following fields in the configuration file:
  ```
  HOME_NET: "<Windows-IP>"
  EXTERNAL_NET: "any"
  default-log-dir: C:\\Suricata\\log
  stats:
  enabled: no
  default-rule-path: C:\\Suricata\\rules\\
  ```
- Rules are not downloaded by default, So you need to download and extract the rules .zip file:
  ```
  curl https://rules.emergingthreats.net/open/suricata-9.0/emerging.rules.zip
  Expand-Archive emerging.rules.zip
  ```
- Move the rules to C:\Program Files\Suricata\rules
- By default Suricata runs as a service on Windows, if this does not happen, you can open a terminal and execute the following commands:
  ```
  .\suricata -c suricata.yaml -i <DEVICE-IP> -l ./log -knone -vvv --service-install
  NET START suricata
  ```
- To start Suricata we must execute the following commands:
  ```
  cd C:\Program Files\Suricata
  ```
  ```
  .\suricata.exe -c suricata.yaml -i <Device-IP>
  ```

### Configuring the Wazuh-Agent
- Open the ossec.conf in C:\Program Files (x86)\ossec-agent\ossec.conf
  ```
  notepad C:\Program Files (x86)\ossec-agent\ossec.conf
  ```
- Add the following snippet to the ossec.conf to forward suricata logs to the wazuh-manager
  ```
  <localfile>
     <log_format>json</log_format>
     <location>C:\Program Files\Suricata\log\eve.json</location>
  </localfile>

- Restart Wazuh-Agent
  ```
  Restart-Service -Name WazuhSvc
  ```
