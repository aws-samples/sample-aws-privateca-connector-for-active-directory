<#
.SYNOPSIS
    Applies required permissions for AWS PrivateCA Connector for Active Directory to the Active Directory Connector service account
.PARAMETER AccountName
    Active Directory Connector service account name
.PARAMETER ChildDomainName
    The fully qualified domain name of the target child domain (ex: child.corp.example.com)
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="Enter the AD Connector service account name")]
    [string]$AccountName,
    [Parameter(Mandatory=$false, HelpMessage="Enter child domain's fully qualified domain name (ex: child.corp.example.com)")]
    [string]$ChildDomainName
)

$ErrorActionPreference = "Stop"

# Gets Active Directory information.
Import-Module -Name 'ActiveDirectory'

$currentDomain= Get-ADDomain

$RootDSE = Get-ADRootDSE

# Check if the current domain is the root domain
if ($currentDomain.DistinguishedName -ne $RootDSE.rootDomainNamingContext) {
    throw "This is a child domain. Run this script on your root domain."
}

# Gets AD Connector service account information
if (-not $ChildDomainName) {
    $AccountProperties = Get-ADUser -Identity $AccountName
} else {
    $AccountProperties = Get-ADUser -Identity $AccountName -Server $ChildDomainName
}

$AccountSid = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' $AccountProperties.SID.Value
[System.GUID]$ServicePrincipalNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'servicePrincipalName' } -Properties 'schemaIDGUID').schemaIDGUID
$AccountAclPath = $AccountProperties.DistinguishedName

if (-not $ChildDomainName) {
    # Gets ACL settings for AD Connector service account.
    $AccountAcl = Get-ACL -Path "AD:\$AccountAclPath"
    # Sets ACL allowing the AD Connector service account the ability to add and remove a Service Principal Name (SPN) to itself
    $AccountAccessRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' $AccountSid, 'WriteProperty', 'Allow', $ServicePrincipalNameGuid, 'None'
    $AccountAcl.AddAccessRule($AccountAccessRule)
    Set-ACL -AclObject $AccountAcl -Path "AD:\$AccountAclPath"
} else {
    # Sets ACL allowing the AD Connector service account the ability to add and remove a Service Principal Name (SPN) to itself
    $AdObject = Get-ADObject -Server $ChildDomainName -Filter "objectSid -eq '$AccountSid'" -Properties nTSecurityDescriptor
    $SecurityDescriptor = $AdObject.nTSecurityDescriptor
    $SELF = New-Object System.Security.Principal.NTAccount("SELF")
    $SPNWriteRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' $SELF, 'WriteProperty', 'Allow', $ServicePrincipalNameGuid, 'None'
    $SecurityDescriptor.AddAccessRule($SPNWriteRule)
    $Creds = Get-Credential -Message "Please enter credentials for an administrator on $ChildDomainName"
    Set-ADObject -Server $ChildDomainName -Identity $AdObject.DistinguishedName -Replace @{nTSecurityDescriptor=$SecurityDescriptor} -Credential $Creds
}

# Add ACLs allowing AD Connector service account the ability to create certification authorities
[System.GUID]$CertificationAuthorityGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'certificationAuthority' } -Properties 'schemaIDGUID').schemaIDGUID
$CAAccessRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' $AccountSid, 'ReadProperty,WriteProperty,CreateChild,DeleteChild', 'Allow', $CertificationAuthorityGuid, 'All'
$PKSDN = "CN=Public Key Services,CN=Services,CN=Configuration,$($RootDSE.rootDomainNamingContext)"
$PKSACL = Get-ACL -Path "AD:\$PKSDN"
$PKSACL.AddAccessRule($CAAccessRule)
Set-ACL -AclObject $PKSACL -Path "AD:\$PKSDN"

$AIADN = "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$($RootDSE.rootDomainNamingContext)"
$AIAACL = Get-ACL -Path "AD:\$AIADN"
$AIAACL.AddAccessRule($CAAccessRule)
Set-ACL -AclObject $AIAACL -Path "AD:\$AIADN"

$CertificationAuthoritiesDN = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$($RootDSE.rootDomainNamingContext)"
$CertificationAuthoritiesACL = Get-ACL -Path "AD:\$CertificationAuthoritiesDN"
$CertificationAuthoritiesACL.AddAccessRule($CAAccessRule)
Set-ACL -AclObject $CertificationAuthoritiesACL -Path "AD:\$CertificationAuthoritiesDN"

$NTAuthCertificatesDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$($RootDSE.rootDomainNamingContext)"
If (-Not (Test-Path -Path "AD:\$NTAuthCertificatesDN")) {
New-ADObject -Name 'NTAuthCertificates' -Type 'certificationAuthority' -OtherAttributes @{certificateRevocationList=[byte[]]'00';authorityRevocationList=[byte[]]'00';cACertificate=[byte[]]'00'} -Path "CN=Public Key Services,CN=Services,CN=Configuration,$($RootDSE.rootDomainNamingContext)" }            

$NTAuthCertificatesACL = Get-ACL -Path "AD:\$NTAuthCertificatesDN"
$NullGuid = [System.GUID]'00000000-0000-0000-0000-000000000000'
$NTAuthAccessRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' $AccountSid, 'ReadProperty,WriteProperty', 'Allow', $NullGuid, 'None'
$NTAuthCertificatesACL.AddAccessRule($NTAuthAccessRule)
Set-ACL -AclObject $NTAuthCertificatesACL -Path "AD:\$NTAuthCertificatesDN"

Write-Output "AD service account permissions delegated successfully."
