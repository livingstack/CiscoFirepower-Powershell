
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()





########################################################################BUILD API CONNECTION HEADERS SECTION##############################################################


$username = "someusername"
$username = "someusername"
$username = "someusername"
$password = Read-Host "please enter password"
$userpass  = $username + “:” + $password
$bytes= [System.Text.Encoding]::UTF8.GetBytes($userpass)
$encodedlogin=[Convert]::ToBase64String($bytes)
$authheader = "Basic " + $encodedlogin
$ipaddress = Read-Host "Please enter ip address of FMC"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization",$authheader)
$headers.Add("Accept","application/json")
$headers.Add("Content-Type","application/json")

$headers.Add("X-auth-access-token","e4cea852-104f-48ce-9a59-75d00524344b")
$headers.Add("X-auth-refresh-token","3388b5c2-c83e-4af9-91d5-33efc5ae3246")

$refreshheaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$refreshheaders.Add("Authorization",$authheader)
$refreshheaders.'X-auth-access-token'= "3ee87dfc-43fa-4faf-ad1b-a1a52ba69a0c"
$refreshheaders."X-auth-refresh-token"= "d6698282-6bc5-4520-ac09-4bf6c926888c"


$headers.'X-auth-access-token'= $refreshheaders.'X-auth-access-token'



$response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post 


#use to refesh the token after the 30 min timeout
$refeshauthtoken = Invoke-WebRequest -Uri $uri -Headers $refreshheaders -Method Post 
$refreshheaders.'X-auth-access-token'= $refeshauthtoken.Headers.'X-auth-access-token'
$refreshheaders."X-auth-refresh-token"= $refeshauthtoken.Headers.'X-auth-refresh-token'


#reassign the refreshed values to main headers for API communication
$headers.'X-auth-access-token'= $refreshheaders.'X-auth-access-token'

##############################################END OF BUILD API CONNECTION HEADERS SECTION###############################################################

########################################################BUILD API CONNECTION URI SECTION: #####################################################################

$uri = "https://ipaddress/api/fmc_platform/v1/auth/generatetoken"

#possibly unnecessary
$IPV4staticroutesuri = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/68b0b1c0-d006-11e7-9a86-d36bd2ca88ea/routing/ipv4staticroutes"
$AllStaticRoutesURI = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/68b0b1c0-d006-11e7-9a86-d36bd2ca88ea/routing/staticroutes"                                             
$deviceIDURI = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
$physicalinterfacesURI = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/68b0b1c0-d006-11e7-9a86-d36bd2ca88ea/physicalinterfaces"
$logicalinterfacesURI = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/68b0b1c0-d006-11e7-9a86-d36bd2ca88ea/fplogicalinterfaces"

$policyassignmentsuri = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments/objectid"
$securityzonesuri = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"

$accesspolicyassignmentsuri ="https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"

#Add firewall list  "PreProd-ASA1.am.kwe.com-ACPolicy-201804061053"  object id to uri below
                                    #|
                                    #V
$aclentriesuri = "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/00000000-0000-0ed3-0000-034359738863/accessrules?limit=250"

#Add first acl entry in firewall list "PreProd-ASA1.am.kwe.com-ACPolicy-201804061053" below
                                    #|
                                    #V
$accessrulesuri= "https://ipaddress/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/00000000-0000-0ed3-0000-034359738863/accessrules/00000000-0000-0ed3-0000-000268435457"
                                                                                                                          #00000000-0000-0ed3-0000-000268435457
                                                                                                                          #00000000-0000-0ed3-0000-034359738863

$ALLObjectsURI
#######################################################################Start Objects URI SECTION################################################################

#Create an arraylist to store all Firepower Oject URL entries
$FirepowerObjectentrieslist = New-Object System.Collections.ArrayList

for (($i=0),($i-lt1);$i++){

$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/anyprotocolportobjects")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applicationfilters")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applicationproductivities")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applicationrisks")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applications")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applicationtags")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applicationtypes")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/certenrollments")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/continents")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/countries")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/dnsservergroups")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/endpointdevicetypes")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/extendedaccesslist")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/fqdns")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/geolocations")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts?expanded=true")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/icmpv4objects")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/icmpv6objects")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev1ipsecproposals")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev1policies")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev2ipsecproposals")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev2policies")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/interfacegroups")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/interfaceobjects")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/isesecuritygrouptags")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/portobjectgroups")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ports")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ranges")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/realms")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/realmusergroups")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/realmusers")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securitygrouptags")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/siurlfeeds")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/siurllists")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/slamonitors")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/tunneltags")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/urlcategories")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/urlgroups")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/urls")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/variablesets")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/vlangrouptags")
$FirepowerObjectentrieslist.Add("https://" + $ipaddress + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/vlantags")

}
#######################################################################END Objects URI SECTION################################################################




#######################################################################END BUILD API CONNECTION URI SECTION################################################################


#Ignore, irrelevant to this script, used for testing
$devicelist = Invoke-WebRequest -Uri $deviceIDURI -Headers $headers -Method Get
#$devicelist.AllElements | Write-Output >> c:\devicelist.txt
#/Ignore


################################################## Interface GROUPS ENTIRIES SECTION:#####################################################################

#GET LIST of all the Access Rules (ACL Entries) associated with the firewall rule "PreProd-ASA1.am.kwe.com-ACPolicy-201804061053"
$Interfacesgroupsentrieslist = Invoke-WebRequest -Uri $interfaceGroupsURI -Headers $headers -Method Get
$AllObjectsEntriesList = Invoke-WebRequest -Uri $ALLObjectsURI -Headers $headers -Method Get

#write gathered data to a text file for easier viewing (if wanted)
$InterfaceGroupsentrieslist.AllElements | Write-Output >> c:\interfacegroupslist.txt

#Create an arraylist to store all converted json entries in $aclentrieslist 
$convertedInterfaceGroupsentrieslist = New-Object System.Collections.ArrayList

#convert them from returned json format and store them temporarily
$tempconvertedInterfaceGroupsentrieslist = ConvertFrom-Json -InputObject $Interfacesgroupsentrieslist

foreach($entry in $tempconvertedInterfaceGroupsentrieslist.items){
$convertedInterfaceGroupsentrieslist.Add($entry)
}

#Remove first index from list since it's already been modified
#Alter - remove it later as future use may require first index

#$convertedInterfaceGroupsentrieslist.RemoveAt(0)


#write them to a text file for easiereasier viewing (if wanted)
$convertedInterfaceGroupsentrieslist[0][0].items | Write-Output >> c:\convertedphysicalinterfaceentries.txt  |  Out-GridView

######################################################/END of INTERFACE Groups ENTRIES SECTION##########################################################################






#Step 4:Build custom URI for each Static route



###################################################### GET EACH Static Route ENTRIE'S PROPERTIES SECTION: ######################################################################

#get the individual attributes configured for the acl entry specified in uri

#$ipv4staticrouteproperties = Invoke-WebRequest -Uri $accessrulesuri -Headers $headers -Method Get
#$AllStaticRouteproperties = Invoke-WebRequest -Uri $accessrulesuri -Headers $headers -Method Get




$convertedObjectsproperties = New-Object System.Collections.ArrayList


#convert them from returned json format and store them temporarily
#$tempaccesspolicyrulesproperties = New-ArrayList
#$tempaccesspolicyrulesproperties = ConvertFrom-Json -InputObject $accesspolicyrulesproperties

$staticRouteEntryCounter = 0
$aclEntryCounter = 0



#Build master list of all acl properties
foreach($objecturi in $FirepowerObjectentrieslist){

#api has a limit of 120 requests per second
if(($StaticRouteEntryCounter -eq 119) -or ($aclEntryCounter -eq 239)){


Start-Sleep -Seconds 60
}


#$staticroutepolicyrulesproperties = Invoke-WebRequest -Uri $masterCustomURIList[$aclentrycounter] -Headers $headers -Method Get

$Objectsproperties = Invoke-WebRequest -Uri $FirepowerObjectentrieslist[-1] -Headers $headers -Method Get

#$staticRouteentrycounter


($Objectsproperties = ($Objectsproperties | ConvertFrom-Json))
$convertedObjectsproperties.Add($Objectsproperties.items)


$staticRouteEntryCounter++
$aclEntryCounter++
}





####################################################END GET EACH ACL ENTRY'S PROPERTIES SECTION: ###################################################################


###################################################### Build EACH Static Route ENTRY PROPERTIES SECTION: ######################################################################


$interfaceName = ""
$selectedNetworksType= "Network"
$overridable="False"
$selectedNetworksName = ""
$gatewayType = "Host"
$gatewayValue = ""
$metricValue = 1
$type = "IPv4StaticRoute"
$isTunnelled = "False"

$selectedNetworksObject = New-Object -TypeName PSobject
            $selectedNetworksObject | Add-Member -MemberType NoteProperty -Name type -Value $selectedNetworksType
            $selectedNetworksObject | Add-Member -MemberType NoteProperty -Name overridable -Value $overridable
            $selectedNetworksObject

$JSONStaticRouteObject= New-Object -TypeName PSobject
            $JSONStaticRouteObject | Add-Member -MemberType NoteProperty -Name id -Value $tempaccesspolicyrulesproperties.id -Force

####################################################END Build EACH ACL ENTRY PROPERTIES SECTION: ###################################################################



####################################################POST UPDATED PROPERTIES FOR EACH ACL ENTRY WITH CUSTOM URI SECTION:####################################################################

#Now create a loop for each item in previous array to do a put request for each source where name matches that has z_perimeter1 and doesn't 
#have pre-prod to post to the custom uri the pre-prod source zone


###########################Change values of tempaccesspolicyrulesproperties to match acl entry properties to PUT to API next#################################

        #####NOTE when object converted from json and stored in variable, that variable becomes "The JSON" object

$securityZones = Invoke-WebRequest -Uri $securityzonesuri  -Headers $headers -Method Get
$convertedSecurityZones = $securityZones | ConvertFrom-Json
        
$backupObject = New-ArrayList
$backupObject = $convertedSecurityZones[0].items | Select-Object -ExcludeProperty links -Property *


$testObject = New-ArrayList


$masterConvertedACLPropertiesList = New-ArrayList
$aclBackup = New-ArrayList

$zoneObject = New-ArrayList

$zoneObjectsArray = New-ArrayList

$preprodobject = New-ArrayList


$z_insideObject = New-ArrayList
$z_outsideObject = New-ArrayList
$z_perimeter4Object = New-ArrayList
$z_perimeter3Object = New-ArrayList
$z_perimeter2Object = New-ArrayList
$z_perimeter1Object = New-ArrayList


        foreach($zonename in $convertedSecurityZones.items){
            $zonename2 = $zonename | Select-Object -ExcludeProperty links -Property *
          foreach($item in $backupObject){
          
                    if(($item.name -match $zonename2.name) -and ($item.name -ne $zonename2.name)){
                        $zoneObject= @($item,$zonename2)
                        $zoneObjectsArray.Add($zoneObject)
                    }
            }
        }

        #assign json perimeter objects to named objects
        foreach($item in $zoneObjectsArray){
          
                    if($item[1].name -eq "Z_perimeter4"){
                        $z_perimeter4Object = $item
                        }
                    if($item[1].name -eq "Z_perimeter3"){
                        $z_perimeter3Object = $item
                        }
                    if($item[1].name -eq "Z_perimeter2"){
                        $z_perimeter2Object = $item
                        }
                    if($item[1].name -eq "Z_perimeter1"){
                        $z_perimeter1Object = $item
                        }
                    if($item[1].name -eq "Z_outside"){
                        $z_outsideObject = $item
                        }
                    if($item[1].name -eq "Z_inside"){
                        $z_insideObject = $item
                        }
            }


$z_insideObject = $z_insideObject #| ConvertTo-Json
$z_outsideObject = $z_outsideObject #| ConvertTo-Json
$z_perimeter4Object = $z_perimeter4Object #| ConvertTo-Json
$z_perimeter3Object = $z_perimeter3Object #| ConvertTo-Json
$z_perimeter2Object = $z_perimeter2Object #| ConvertTo-Json
$z_perimeter1Object = $z_perimeter1Object #| ConvertTo-Json



foreach($jsonobject in $masterACLPropertiesList){

$convertedBackupObject = $jsonobject | ConvertFrom-Json
$aclBackup.Insert(0,$convertedBackupObject)

#if($masterConvertedACLPropertiesList.Count -eq 0){

        $masterConvertedACLPropertiesList.Add(($jsonobject | ConvertFrom-Json))
#        }
}


$backupMasterConvertedACLPropertiesList = $masterConvertedACLPropertiesList

$objectCounter = 0;

$ZoneReassignmentErrors = New-ArrayList

foreach($jsonobject in $masterACLPropertiesList){

#Check the source zones
if(($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects[0].name -eq "Z_perimeter4")){

$masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects = $z_perimeter4Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects[0].name -eq "Z_perimeter3")){

$masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects = $z_perimeter3Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects[0].name -eq "Z_perimeter2")){

$masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects = $z_perimeter2Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects[0].name -eq "Z_perimeter1")){

$masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects = $z_perimeter1Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects[0].name -eq "Z_inside")){

$masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects = $z_insideObject
}

if(($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects.Count -eq 1)-and ($masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects[0].name -eq "Z_outside")){

$masterConvertedACLPropertiesList[$objectCounter].sourceZones.objects = $z_outsideObject
}

#Check the destination zones

if(($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects[0].name -eq "Z_perimeter4")){

$masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects = $z_perimeter4Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects[0].name -eq "Z_perimeter3")){

$masterConvertedACLPropertiesList[$objectCounter].destinationZones.objectss = $z_perimeter3Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects[0].name -eq "Z_perimeter2")){

$masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects = $z_perimeter2Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects[0].name -eq "Z_perimeter1")){

$masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects = $z_perimeter1Object
}

if(($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects[0].name -eq "Z_inside")){

$masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects = $z_insideObject
}

if(($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects.Count -eq 1) -and ($masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects[0].name -eq "Z_outside")){

$masterConvertedACLPropertiesList[$objectCounter].destinationZones.objects = $z_outsideObject
} 

if($? -eq $false){

$ZoneReassignmentErrors.Add(@($jsonobject,$Error[0]))


}

$objectCounter++

} 


###########################Now convert to JSON and post all the objects just created###########################################################

$ZonePropertiesPutErrors = New-ArrayList



#Example
#$masterConvertedACLPropertiesList[0].sourceZones.objects.ForEach({ConvertTo-Json($_)})
#/Example



$FinalACLPropertiesPutObjectList = New-ArrayList

$FinalACLPropertiesPutObjectList.Clear()


foreach($object in $masterConvertedACLPropertiesList){

#$FinalACLPropertiesPutObjectList.Add( ($object | Where-Object {(-notlike "metadata" -and -notlike "links")}  Select-Object  id,sourceZones,destinationZones,sourceNetworks,destinationNetworks,logBegin,sourcePorts,destinationPorts,logEnd,logFiles,sendEventsToFMC,action,type,enabled,name))
$FinalACLPropertiesPutObjectList.Add( ($object | Select-Object -ExcludeProperty metadata,links,commentHistoryList -property *))
}

$testvalue = 0
$alternateMasterConvertedACLPropertiesList = New-ArrayList
                
foreach($someValue in $FinalACLPropertiesPutObjectList){
          
$alternateMasterConvertedACLPropertiesList.Add(($someValue | ConvertTo-Json -Depth 3))

$testvalue++
}                                




$URIPutCounter = 0
$putBody
$apiResponse
$masterAPIResponselist = New-ArrayList

$session
$errorvariable
$warningvariable
$informationvariable

foreach($zone in $masterConvertedACLPropertiesList){
#$masterConvertedACLPropertiesList.Count

$putBody = $alternateMasterConvertedACLPropertiesList[$URIPutCounter]

#api has a limit of 120 requests per second
#put is so much slower, it's not needed.....
#if(($URIPutCounter -eq 119) -or ($URIPutCounter -eq 239)){
#Start-Sleep -Seconds 60
#}


$apiResponse = Invoke-WebRequest -Uri $masterCustomURIList[$URIPutCounter] -Headers $headers -WebSession $session -Method Put -Body $putBody -ErrorVariable $errorvariable -InformationVariable $informationvariable -WarningVariable $warningvariable

   


if($? -eq $false){

$ZonePropertiesPutErrors.Add(@($zone,$Error[0]))


}

$masterAPIResponselist.Add($apiResponse)
$URIPutCounter++


}

#Write results of bulk put to text file
$masterAPIResponselist | ConvertFrom-Json | Write-Output >> c:\masterAPIResponselist.txt


#BUILD TEST OBJECT
<#
$JSONPutObject = New-Object -TypeName PSobject
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name id -Value $tempaccesspolicyrulesproperties.id -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name sourceZones -Value $tempaccesspolicyrulesproperties.sourceZones -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name sourceNetworks -Value $tempaccesspolicyrulesproperties.sourceNetworks -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name destinationNetworks -Value $tempaccesspolicyrulesproperties.destinationNetworks -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name logBegin -Value  $tempaccesspolicyrulesproperties.logBegin -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name sourcePorts -Value  $tempaccesspolicyrulesproperties.sourcePorts -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name logEnd -Value  $tempaccesspolicyrulesproperties.logEnd -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name logFiled -Value  $tempaccesspolicyrulesproperties.logFiled -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name sendEventsToFMC -Value  $tempaccesspolicyrulesproperties.sendEventsToFMC -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name action -Value  $tempaccesspolicyrulesproperties.action -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name type -Value  $tempaccesspolicyrulesproperties.type -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name enable -Value  $tempaccesspolicyrulesproperties.enabled -Force
            $JSONPutObject | Add-Member -MemberType NoteProperty -Name name -Value  $tempaccesspolicyrulesproperties.name -Force
            #>








####################################################END UPDATED PROPERTIES FOR EACH ACL ENTRY WITH CUSTOM URI SECTION####################################################################