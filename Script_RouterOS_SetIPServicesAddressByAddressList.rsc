#RouterOS - Set ip services address based on Address-list

#This script takes the IPv4 and IPv6 from an specified address-list
#and applies these IPs as allowed addresses in "/ip/services address".

#Using this script, and also the dynamic FQDN resolutions resource
#of RouterOS, you can for example set a FQDN that contains all the
#IP sources you use to manage your RouterOS equiments.

#Created by Douglas Fischer August 2022.

{
#Define here, separeted by semicolon ";", the services you want
#the script set the address protection.
#Values here must match exactly with the names of the service in RouterOS.
:local servicesToApplyAddressList {"api";"api-ssl";"ftp";"ssh";"telnet";"winbox";"www";"www-ssl"};

#Define here the name of the address-list that contains the
#origins allowed to access the services of this mikrotik.
#The script will look for IPv4 and IPv6 address-lists with that name.
#If it exists, it will process and place in the allowed
#addresses for each of the defined services.
:local nameOfAddressList IPsDeGerencia;

#Define here the maximum number of entries that the
#script will apply in the "address" of each service.
#Address-Lists can have a huge amount of entries.
#But if you put a number of entries in "address" of "/ip/services",
#this can affect the proper functioning of the equipment, in addition
#to being an indication that this block is too permissive.
:local maxAddressEntriesInIpServices 10;

#Define here the minimum number of entries that the
#script will apply in the "address" of each service.
#The smaller recommended value is "1".
#If you set it to "0" and by some reason the firewall
#address-list become empyt, the script will remove the
#protection of the services.
:local minAddressEntriesInIpServices 1;

#Do not change anything below this line.
:local arrayIndexesAddressListv4 [ /ip/firewall/address-list/find where list=$nameOfAddressList disabled=no ];
:local arrayIndexesAddressListv6 [ /ipv6/firewall/address-list/find where list=$nameOfAddressList disabled=no ];
:local lenArrayAddressListIndex [ ([ :len $arrayIndexesAddressListv4 ] + [ :len $arrayIndexesAddressListv6 ]) ];
:local stringNewAddressIPService;

:put $lenArrayAddressListIndex;

:if ( $lenArrayAddressListIndex < $minAddressEntriesInIpServices ) do={
    :log info "Number of prefixes ($lenArrayAddressListIndex) on address-list $nameOfAddressList is below the minimum specified on parameter on script ($minAddressEntriesInIpServices). No changes on ip services address will be done."
} else={
    :if ( $lenArrayAddressListIndex > $maxAddressEntriesInIpServices ) do={
        :log info "Number of prefixes ($lenArrayAddressListIndex) on address-list $nameOfAddressList is above the maximum specified on parameter on script ($maxAddressEntriesInIpServices). No changes on ip services address will be done."
    } else={
        :foreach i in $arrayIndexesAddressListv4 do={
            :local indexInAddressList [ ($i) ];
            :local addressInAddressList [ /ip/firewall/address-list/get $indexInAddressList address ];
            :if ( $addressInAddressList ~"^((25[0-5]|(2[0-4]|[01]\?[0-9]\?)[0-9])\\.){3}(25[0-5]|(2[0-4]|[01]\?[0-9]\?)[0-9])\\/(3[0-2]|[0-2]\?[0-9])\$" ) do={
                #IPv4-Prefix
                :set stringNewAddressIPService "$stringNewAddressIPService,$addressInAddressList";
            } else={

                :if ( $addressInAddressList ~"^((25[0-5]|(2[0-4]|[01]\?[0-9]\?)[0-9])\\.){3}(25[0-5]|(2[0-4]|[01]\?[0-9]\?)[0-9])\$" ) do={
                #IPv4-Address
                :set stringNewAddressIPService "$stringNewAddressIPService,$addressInAddressList/32";
                } else={
                    #:log info "$addressInAddressList is not an IPv4-Prefix or an IPv4-Address, probably an FQDN. Will not be added to address on ip>services."
                };
            };
        };
        :foreach i in $arrayIndexesAddressListv6 do={
            :local indexInAddressList [ ($i) ];
            :local addressInAddressList [ /ipv6/firewall/address-list/get $indexInAddressList address ];
            :if ( $addressInAddressList ~"^(([0-9a-fA-F]{1,4}\\:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}\\:){1,7}\\:|([0-9a-fA-F]{1,4}\\:){1,6}\\:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}\\:){1,5}(\\:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}\\:){1,4}(\\:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}\\:){1,3}(\\:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}\\:){1,2}(\\:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}\\:((\\:[0-9a-fA-F]{1,4}){1,6})|\\:((\\:[0-9a-fA-F]{1,4}){1,7}|\\:))" ) do={
                #IPv6-Prefix or IPv6-Address (no IPv6-nestmask matcher at the end ^\\/(1[0-2]\?[0-9]|[0-9]\?[0-9])\$ )
                :set stringNewAddressIPService "$stringNewAddressIPService,$addressInAddressList";
            } else={
                #:log info "$addressInAddressList is not an IPv6-Prefix or an IPv6-Address, probably an FQDN. Will not be added to address on ip>services."
            };
        };
        :foreach i in $servicesToApplyAddressList do={
            :local nameOfServiceInListToApply [ ($i) ];
            #Needs to convert and reconvert to compare as string and avoid unnecessary changes.
            :local strArrayNewAddressIPService [ :tostr [ :toarray $stringNewAddressIPService ] ];
            :local strCurrentAddressIPService [ :tostr [/ip service get [ find where name=$nameOfServiceInListToApply ] address ] ];
            :if (  $strArrayNewAddressIPService != $strCurrentAddressIPService ) do={
                #:log info "Address-list $nameOfAddressList and ip>services>$nameOfServiceInListToApply address do not match. $nameOfServiceInListToApply address will be changed."
                /ip/service/set [ find where name=$nameOfServiceInListToApply name ] address="$stringNewAddressIPService";
            } else={
                #:log info "Address-list $nameOfAddressList and ip>services>$nameOfServiceInListToApply address matches. Nothing to be done."
            };
        };
    };
};
}