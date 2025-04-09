/ip firewall address-list add address=172.16.200.0/22 list=trustedSourcesForManagement
/ip firewall address-list add address=10.11.12.13 list=trustedSourcesForManagement

/system script add dont-require-permissions=no name=blockSourcesForLoginFailure owner=Master policy=read,write source="# RouterOS - Script \"blockSourcesForLoginFailure\"\r\
    \n# Logs Possible Brute Force against loca users\r\
    \n# Blocks the IPv4 and IPv6 sources that exceeded the max failure login attempts\r\
    \n\r\
    \n:local trustedMgmtSrcAddressList    \"trustedSourcesForManagement\"\r\
    \n:local intervalToScheduleThisScript \"1m\"\r\
    \n:local loginFailureMaxAttempts      3\r\
    \n:local loginFailureTimeoutToBlock   \"24h\"\r\
    \n:local loginFailureTimeRangeToCount \"1h\"\r\
    \n:local loginFailureMsgString        \"login failure for user \"\r\
    \n:local loginFailureAddressList      \"blockedSourcesForLoginFailure\"\r\
    \n:local logBuffer                    \"loginFailureBuffer\"\r\
    \n:local thisScriptName               \"blockSourcesForLoginFailure\"\r\
    \n:local loginFailureSourceArray      [:toarray \"\"]\r\
    \n:local loginFailureUserArray        [:toarray \"\"]\r\
    \n:local logMsgFrom                   \" from \"\r\
    \n:local logMsgVia                    \" via \"\r\
    \n\r\
    \n# Limit script execution to single instance\r\
    \n:if ([/system script job print count-only as-value where script=[:jobname] ] > 1) do={\r\
    \n  :error \"script instance already running\"\r\
    \n  }\r\
    \n\r\
    \n# Check if this script is running with the expected name\r\
    \n:if ([:jobname] != \$thisScriptName) do={\r\
    \n    /system script set [find where name=[:jobname]] name=\$thisScriptName\r\
    \n}\r\
    \n\r\
    \n# Check if this script is scheduled as expected\r\
    \n/system scheduler\r\
    \n:if ([:len [find where name=\$thisScriptName]] = 0) do={\r\
    \n    add name=\$thisScriptName on-event=\$thisScriptName \\\r\
    \n        policy=read,write start-date=1970-01-01 start-time=00:00:00\\\r\
    \n        interval=\$intervalToScheduleThisScript\r\
    \n}\r\
    \n\r\
    \n# Check if the needed log actions and rules exist. If not, create it.\r\
    \n/system logging \r\
    \n:if ([:len [action find where (name=\"\$logBuffer\" and target=memory)]] = 0) do={\r\
    \n    action add name=\"\$logBuffer\" target=memory;\r\
    \n}\r\
    \n:if ([:len [find where (action=\"\$logBuffer\" and regex~\"\$loginFailureMsgString\" and \\\r\
    \n                        topics~\"system\" and topics~\"error\" and topics~\"critical\" and \\\r\
    \n                        disabled=no)]] = 0) do={\r\
    \n    add action=\"\$logBuffer\" regex=\"^\$loginFailureMsgString\" topics=system,error,critical;\r\
    \n}\r\
    \n\r\
    \n# Check if the firewall raw rules to protect from brute force exists.\r\
    \n/ip firewall raw\r\
    \n:if ([:len [find where src-address-list=\"\$loginFailureAddressList\"]] = 0) do={\r\
    \n    add action=drop chain=prerouting src-address-list=\$loginFailureAddressList \\\r\
    \n    comment=\"Allow Trusted Sources to arrive\"\r\
    \n}\r\
    \n:if ([:len [find where src-address-list=\"\$trustedMgmtSrcAddressList\"]] = 0) do={\r\
    \n    add action=accept chain=prerouting src-address-list=\$trustedMgmtSrcAddressList \\\r\
    \n    place-before=[find where src-address-list=\"\$loginFailureAddressList\"] \\\r\
    \n    comment=\"Allow Trusted Sources to arrive\"\r\
    \n}\r\
    \n/ipv6 firewall raw\r\
    \n:if ([:len [find where src-address-list=\"\$loginFailureAddressList\"]] = 0) do={\r\
    \n    add action=drop chain=prerouting src-address-list=\$loginFailureAddressList \\\r\
    \n    comment=\"Allow Trusted Sources to arrive\"\r\
    \n}\r\
    \n:if ([:len [find where src-address-list=\"\$trustedMgmtSrcAddressList\"]] = 0) do={\r\
    \n    add action=accept chain=prerouting src-address-list=\$trustedMgmtSrcAddressList \\\r\
    \n    place-before=[find where src-address-list=\"\$loginFailureAddressList\"] \\\r\
    \n    comment=\"Allow Trusted Sources to arrive\"\r\
    \n}\r\
    \n\r\
    \n# Get the log messages from specified buffer on the specified time range \r\
    \n/log\r\
    \n:foreach logBufferItem in=[find where (((([:timestamp]+([/system clock get gmt-offset].\"s\"))-[:totime (time)]) <= \$loginFailureTimeRangeToCount) and (buffer=\"\$logBuffer\"))] do={\r\
    \n    :local logBufferMessage [get \$logBufferItem message];\r\
    \n    :if ((\$logBufferMessage~\$loginFailureMsgString) and (\$logBufferMessage~\$logMsgFrom) and (\$logBufferMessage~\$logMsgVia)) do={\r\
    \n        \r\
    \n        :local userLoginFailed    [:pick \$logBufferMessage ([:find \$logBufferMessage \$loginFailureMsgString -1] + [:len \$loginFailureMsgString]) [:find \$logBufferMessage \$logMsgFrom -1]];\r\
    \n        :local sourceLoginFailed  [:pick \$logBufferMessage ([:find \$logBufferMessage \$logMsgFrom -1] + [:len \$logMsgFrom]) [:find \$logBufferMessage \$logMsgVia -1]];\r\
    \n        #:local serviceLoginFailed [:pick \$logBufferMessage ([:find \$logBufferMessage \$logMsgVia -1] + [:len \$logMsgVia]) [:len \$logBufferMessage]];\r\
    \n        \r\
    \n        # Counting login failure per user\r\
    \n        :if ([:typeof ((\$loginFailureUserArray)->\$userLoginFailed)] = \"nothing\") do={\r\
    \n            :set ((\$loginFailureUserArray)->\$userLoginFailed) 1\r\
    \n        } else={\r\
    \n            :set ((\$loginFailureUserArray)->\$userLoginFailed) (((\$loginFailureUserArray)->\$userLoginFailed) + 1)\r\
    \n        }\r\
    \n        # Counting login failure per user\r\
    \n        :if ([:typeof ((\$loginFailureSourceArray)->\$sourceLoginFailed)] = \"nothing\") do={\r\
    \n            :set ((\$loginFailureSourceArray)->\$sourceLoginFailed) 1\r\
    \n        } else={\r\
    \n            :set ((\$loginFailureSourceArray)->\$sourceLoginFailed) (((\$loginFailureSourceArray)->\$sourceLoginFailed) + 1)\r\
    \n        }\r\
    \n    }\r\
    \n}    \r\
    \n\r\
    \n# Check if valid local users are under brute force attack and log\r\
    \n/user\r\
    \n:foreach userFailed,failedAttemptsPerUser in=[\$loginFailureUserArray] do={\r\
    \n    :if ((\$failedAttemptsPerUser) >= (\$loginFailureMaxAttempts)) do={\r\
    \n        :if ([:len [find where name=\"\$userFailed\"]] != 0) do={\r\
    \n            :log warning \"\$thisScriptName: Local user \$userFailed is probably under brute force attack. \$failedAttemptsPerUser attempts during last \$loginFailureTimeRangeToCount\"\r\
    \n        }\r\
    \n    }\r\
    \n}\r\
    \n\r\
    \n# Add to specified address list the sources that should be blocke for exceedin the max failure login attempts \r\
    \n/\r\
    \n:foreach sourceFailed,failedAttemptsPerSource in=[\$loginFailureSourceArray] do={\r\
    \n    :if ((\$failedAttemptsPerSource) >= (\$loginFailureMaxAttempts)) do={\r\
    \n        :if (\$sourceFailed~\"^((25[0-5]|(2[0-4]|[01]\\\?[0-9]\\\?)[0-9])\\\\.){3}(25[0-5]|(2[0-4]|[01]\\\?[0-9]\\\?)[0-9])\\\$\") do={\r\
    \n            /ip firewall address-list\r\
    \n            :if ([:len [find where list=\$loginFailureAddressList and address=\$sourceFailed]] <= 0) do={\r\
    \n                add list=\$loginFailureAddressList address=\$sourceFailed comment=\"\$logBufferMessage\" timeout=\"\$loginFailureTimeoutToBlock\"\r\
    \n            }\r\
    \n        } \r\
    \n        :if (\$sourceFailed~\"^(([0-9a-fA-F]{1,4}\\\\:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}\\\\:){1,7}\\\\:|([0-9a-fA-F]{1,4}\\\\:){1,6}\\\\:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}\\\\:){1,5}(\\\\:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}\\\\:){1,4}(\\\\:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}\\\\:){1,3}(\\\\:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}\\\\:){1,2}(\\\\:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}\\\\:((\\\\:[0-9a-fA-F]{1,4}){1,6})|\\\\:((\\\\:[0-9a-fA-F]{1,4}){1,7}|\\\\:))\") do={\r\
    \n            /ipv6 firewall address-list\r\
    \n            # Needed because attribute address from IPv6 address-list comes with mask even for hosts\r\
    \n            :local sourceFailedwithMask128 \"\$sourceFailed/128\"\r\
    \n            :if ([:len [find where (list=\$loginFailureAddressList and address=\$sourceFailedwithMask128)]] <= 0) do={\r\
    \n                add list=\$loginFailureAddressList address=\$sourceFailed comment=\"\$logBufferMessage\" timeout=\"\$loginFailureTimeoutToBlock\"\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n}\r\
    \n"
#
/system script run blockSourcesForLoginFailure
