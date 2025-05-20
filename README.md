## My Project

This repository contains a PowerShell script (`adc-permissions.ps1`) that delegates the necessary permissions to your Active Directory trust store. This script is only for customers who want to use AWS Private CA Connector for Active Directory (C4AD) with an [AD Connector](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_ad_connector.html) directory. 

## Purpose
- Automates the delegation of required permissions for AWS Private CA Connector for AD.
- Prevents permission-related errors during connector setup.

## Prerequisites
- Windows Server with Active Directory and the Active Directory PowerShell module installed.
- Sufficient privileges to modify permissions in your AD environment.

## Usage
Run the script in a PowerShell session with administrative privileges:

   ```powershell
   .\adc-permissions.ps1 -AccountName serviceAccountName
   ```
   
> **Note:** This script only works on root domains. If executed in a child domain, the script will display a warning and will not proceed. Ensure you are running the script in the root domain of your Active Directory forest.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

