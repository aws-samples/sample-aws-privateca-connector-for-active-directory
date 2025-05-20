param(
    [string]$AccountName
)

if (-not $AccountName) {
    $AccountName = Read-Host "Enter the AD Connector service account name"
}

# DO NOT modify anything below this comment.
# Getting Active Directory information.
Import-Module -Name 'ActiveDirectory'

$currentDomain= Get-ADDomain

$RootDSE = Get-ADRootDSE

# Check if the current domain is the root domain

if ($currentDomain.DistinguishedName -eq $RootDSE.rootDomainNamingContext) {

Write-Output "This is a root domain that supports PCA connector configuration."

} else {

Write-Warning "This is a child domain. You must set up the PCA connector with the root domain:" $RootDSE.rootDomainNamingContext

}

# Getting AD Connector service account information
$AccountProperties = Get-ADUser -Identity $AccountName
$AccountSid = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' $AccountProperties.SID.Value
[System.GUID]$ServicePrincipalNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'servicePrincipalName' } -Properties 'schemaIDGUID').schemaIDGUID
$AccountAclPath = $AccountProperties.DistinguishedName

# Getting ACL settings for AD Connector service account.
$AccountAcl = Get-ACL -Path "AD:\$AccountAclPath"

# Setting ACL allowing the AD Connector service account the ability to add and remove a Service Principal Name (SPN) to itself
$AccountAccessRule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' $AccountSid, 'WriteProperty', 'Allow', $ServicePrincipalNameGuid, 'None'
$AccountAcl.AddAccessRule($AccountAccessRule)
Set-ACL -AclObject $AccountAcl -Path "AD:\$AccountAclPath"

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
				