# SURICATA-Installation-Integration-with-wazuh
This repository contains the installation and integration guide for suricata with wazuh

## ➡️ Install Suricata on Ubuntu 
  ```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
  ```
## ➡️ Download and extract the emerging threats suricata ruleset
  ```bash
 cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
 sudo tar -xvzf emerging.rules.tar.gz && sudo mkdir /etc/suricata/rules && sudo mv rules/*.rules /etc/suricata/rules/
 sudo chmod 640 /etc/suricata/rules/*.rules
 ```
## ➡️Modify Suricata settings in the suricata configuration file
 ```bash
  nano /etc/suricata/suricata.yaml
 ```
## ➡️Add/update the following configurations
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
 ## ➡️Restart the Suricata Service
 ```bash
    systemctl restart suricata
```

 ## ➡️Add the following configuration to the /var/ossec/etc/ossec.conf file of the wazuh manager (if suricata is installed on agent then configure agent file). This allows wazuh manager/agent to read the Suricata logs file:

  ```bash
    <ossec_config>
        <localfile
            <log_format>json</log_format>
            <location>/var/log/suricata/eve.json</location>
       </localfile>
    </ossec_config>
 ```
 ## ➡️Restart the Wazuh manager/agent to apply the changes
   ```bash
    systemctl restart wazuh-manager
  ```

  ### 	Wazuh automatically parses data from /var/log/suricata/eve.json & generates related alerts on the Wazuh dashboard.
