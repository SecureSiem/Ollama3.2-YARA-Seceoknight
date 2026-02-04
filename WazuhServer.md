# Wazuh server
Perform the following steps on the Wazuh server to configure custom rules, decoders, and the Active Response module.

1. Add the following decoders to the Wazuh server /var/ossec/etc/decoders/local_decoder.xml file to parse the data in YARA scan result

<!--
  YARA Decoder
-->

    <decoder name="YARA_decoder">
      <prematch>wazuh-YARA:</prematch>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">wazuh-YARA: (\S+)</regex>
      <order>YARA.log_type</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">Scan result: (\S+)\s+</regex>
      <order>YARA.rule_name</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">\[description="([^"]+)",</regex>
      <order>YARA.rule_description</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">author="([^"]+)",</regex>
      <order>YARA.rule_author</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">reference="([^"]+)",</regex>
      <order>YARA.reference</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">date="([^"]+)",</regex>
      <order>YARA.published_date</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">score =(\d+),</regex>
      <order>YARA.threat_score</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">customer="([^"]+)",</regex>
      <order>YARA.api_customer</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">hash1="([^"]+)",</regex>
      <order>YARA.file_hash</order>  
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">tags="([^"]+)",</regex>
      <order>YARA.tags</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">minimum_YARA="([^"]+)"\]</regex>
      <order>YARA.minimum_YARA_version</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">\] (.*) \|</regex>
      <order>YARA.scanned_file</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">chatgpt_response: (.*)</regex>
      <order>YARA.chatgpt_response</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">Successfully deleted (.*)</regex>
      <order>YARA.file_deleted</order>
    </decoder>

    <decoder name="YARA_child">
      <parent>YARA_decoder</parent>
      <regex type="pcre2">Unable to delete (.*)</regex>
      <order>YARA.file_not_deleted</order>
    </decoder>

2. Add the following rules to the /var/ossec/etc/rules/local_rules.xml file. The rules detect FIM events in the monitored directory. This triggers the YARA Active response script to delete a file if identified as a malicious file.

       <group name="syscheck,">
        <rule id="100300" level="5">
         <if_sid>550</if_sid>
         <field name="file">/home</field>
         <description>File modified in /home directory.</description>
        </rule>

        <rule id="100301" level="5">
          <if_sid>554</if_sid>
          <field name="file">/home</field>
          <description>File added to /home directory.</description>
        </rule>
        <rule id="100302" level="5">
          <if_sid>550</if_sid>
          <field name="file" type="pcre2">(?i)C:\\Users.+Downloads</field>
          <description>File modified in the downloads directory.</description>
        </rule>

        <rule id="100303" level="5">
          <if_sid>554</if_sid>
          <field name="file" type="pcre2">(?i)C:\\Users.+Downloads</field>
          <description>File added to the downloads directory.</description>
        </rule>
        </group>

        <group name="yara,">
        <rule id="108000" level="0">
          <decoded_as>YARA_decoder</decoded_as>
          <description>YARA grouping rule</description>
        </rule>
        <rule id="108001" level="10">
          <if_sid>108000</if_sid>
          <match>wazuh-YARA: INFO - Scan result: </match>
          <description>File "$(YARA.scanned_file)" is a positive match for YARA rule: $(YARA.rule_name)</description>
        </rule>

        <rule id="108002" level="5">
          <if_sid>108000</if_sid>
          <field name="yara.file_deleted">\.</field>
          <description>Active response successfully removed malicious file "$(YARA.file_deleted)"</description>
        </rule>

        <rule id="108003" level="12">
          <if_sid>108000</if_sid>
          <field name="YARA.file_not_deleted">\.</field>
          <description>Active response unable to delete malicious file "$(YARA.file_not_deleted)"</description>
        </rule>
        </group>

3. Add the following configuration to the Wazuh server /var/ossec/etc/ossec.conf configuration file. This configures the Active Response module to trigger after the rules with ID 100300, 100301, 100302, and 100303 are fired:

        <ossec_config>
         <command>
           <name>yara_windows</name>
           <executable>yara.exe</executable>
           <timeout_allowed>no</timeout_allowed>
         </command>

        <command>
          <name>yara_linux</name>
          <executable>yara.sh</executable>
          <extra_args>-yara_path /usr/local/bin -yara_rules /var/ossec/active-response/yara/rules/yara_rules.yar</extra_args>
          <timeout_allowed>no</timeout_allowed>
        </command>

        <active-response>
          <disabled>no</disabled>
          <command>yara_linux</command>
          <location>local</location>
          <rules_id>100300,100301</rules_id>
        </active-response>

        <active-response>
          <disabled>no</disabled>
          <command>yara_windows</command>
          <location>local</location>
          <rules_id>100302,100303</rules_id>
        </active-response>
       </ossec_config>
