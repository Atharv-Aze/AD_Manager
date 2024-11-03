<#
.SYNOPSIS
    Advanced Active Directory Management System

.DESCRIPTION
    This PowerShell script provides a menu-driven interface for managing user accounts within an Active Directory environment. 
    It allows administrators to perform tasks such as retrieving domain controller information, listing organizational units (OUs), 
    viewing user details, and disabling user accounts.

.AUTHOR
    Atharv Joshi

.COPYRIGHT
    Copyright © 2023 Atharv Joshi. All rights reserved.

.LICENSE
    This script is provided as-is without any warranty. Use at your own risk.
#>


# Function to display the menu
function Show-Menu {
    Clear-Host
    Write-Host 
    Write-Host " Advanced Active Directory Management System: by Atharv Joshi  " -ForegroundColor Cyan
    Write-Host 
    Write-Host "1. Get Domain Controller Information" -ForegroundColor Yellow
    Write-Host "2. List All OUs in a Parent OU" -ForegroundColor Yellow
    Write-Host "3. List Users Without EmployeeID" -ForegroundColor Yellow
    Write-Host "4. Update EmployeeID from CSV Using Display Name" -ForegroundColor Yellow
    Write-Host "5. Create New AD User" -ForegroundColor Yellow
    Write-Host "6. Disable a User Account" -ForegroundColor Yellow  # New option added
    Write-Host "7. Exit" -ForegroundColor Yellow
    Write-Host 
}

# Function to get domain controller information
function Get-DomainControllerInfo {
    while ($true) {
        Clear-Host
        Write-Host "Fetching domain controller information..."
        try {
            Get-ADDomainController -Filter * | Format-Table Name, IPv4Address, Site, OperatingSystem, Forest
        } catch {
            Write-Host "Error fetching domain controller info: $_" -ForegroundColor Red
        }
        Write-Host "Press Enter to return to the menu or type 'exit' to quit..."
        $input = Read-Host
        if ($input -eq 'exit') { return }
        if ($input -eq '') { break }
    }
}

# Function to list all OUs in a parent OU
function List-OUs {
    while ($true) {
        Import-Module ActiveDirectory
        $parentOU = Read-Host -Prompt "Enter the parent OU location (e.g., 'OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local')"

        if ([string]::IsNullOrWhiteSpace($parentOU)) {
            Write-Host "Parent OU location cannot be empty. Exiting script."
            return
        }

        Clear-Host
        Write-Host "Listing all OUs in the specified parent OU..."
        try {
            $OUs = Get-ADOrganizationalUnit -Filter * -SearchBase $parentOU -Properties DistinguishedName
            if ($OUs) {
                foreach ($OU in $OUs) {
                    Write-Output "Name: $($OU.Name)"
                    Write-Output "Distinguished Name: $($OU.DistinguishedName)"
                    Write-Output "-----------------------------"
                }
            } else {
                Write-Output "No OUs found within the specified parent OU."
            }
        } catch {
            Write-Host "Error fetching OUs: $_" -ForegroundColor Red
        }
        Write-Host "Press Enter to return to the menu or type 'exit' to quit..."
        $input = Read-Host
        if ($input -eq 'exit') { return }
        if ($input -eq '') { break }
    }
}

# Function to list users without EmployeeID
function List-UsersWithoutEmployeeID {
    while ($true) {
        Import-Module ActiveDirectory
        $ouLocation = Read-Host -Prompt "Enter the OU location (e.g., 'OU=Employees,OU=Azelis SA,DC=azelis,DC=local')"

        if ([string]::IsNullOrWhiteSpace($ouLocation)) {
            Write-Host "OU location cannot be empty. Exiting script."
            return
        }

        Clear-Host
        Write-Host "Fetching users without EmployeeID..."
        try {
            $Users = Get-ADUser -Filter * -SearchBase $ouLocation -Properties EmployeeID, Mail, UserPrincipalName
            $UsersWithoutEmployeeID = $Users | Where-Object { -not $_.EmployeeID }
            $UsersWithoutEmployeeID | Select-Object DisplayName, SamAccountName, Mail, @{Name="Email";Expression={$_.Mail -or $_.UserPrincipalName}} | Format-Table -AutoSize
        } catch {
            Write-Host "Error fetching users: $_" -ForegroundColor Red
        }
        Write-Host "Press Enter to return to the menu or type 'exit' to quit..."
        $input = Read-Host
        if ($input -eq 'exit') { return }
        if ($input -eq '') { break }
    }
}

# Function to update EmployeeID from CSV
function Update-EmployeeID {
    while ($true) {
        Import-Module ActiveDirectory
        $csvFilePath = Read-Host -Prompt "Enter the full path to the CSV file (e.g., 'C:\path\to\EmployeeIDs.csv')"
        $ouLocation = Read-Host -Prompt "Enter the OU location (e.g., 'OU=Employees,OU=Azelis SA,DC=azelis,DC=local')"

        if ([string]::IsNullOrWhiteSpace($ouLocation)) {
            Write-Host "OU location cannot be empty. Exiting script."
            return
        }

        if (-not (Test-Path $csvFilePath)) {
            Write-Host "CSV file not found. Exiting script."
            return
        }

        Clear-Host
        Write-Host "Updating EmployeeID based on CSV file..."
        try {
            Import-Csv $csvFilePath | ForEach-Object {
                $displayName = $_.DisplayName
                $newEmployeeID = $_.NewEmployeeID

                $user = Get-ADUser -Filter {DisplayName -eq $displayName} -SearchBase $ouLocation

                if ($user) {
                    Set-ADUser -Identity $user -EmployeeID $newEmployeeID
                    Write-Output "Employee ID for user with display name '$displayName' has been updated to $newEmployeeID."
                } else {
                    Write-Output "User with display name '$displayName' not found in the specified OU."
                }
            }
        } catch {
            Write-Host "Error updating EmployeeID: $_" -ForegroundColor Red
        }
        Write-Host "Press Enter to return to the menu or type 'exit' to quit..."
        $input = Read-Host
        if ($input -eq 'exit') { return }
        if ($input -eq '') { break }
    }
}

# Function to create a new AD user
function Create-NewADUser {
    while ($true) {
        Clear-Host
        Write-Host "Creating a new Active Directory user..."

        # Prompt for user details
        $FirstName = Read-Host "Enter the first name"
        $LastName = Read-Host "Enter the last name"
        $DisplayName = Read-Host "Enter the display name"
        $Email = Read-Host "Enter the email address"
        $Username = Read-Host "Enter the user logon name (sAMAccountName)"
        $EmployeeID = Read-Host "Enter the employee ID"
        $Password = Read-Host "Enter the password" -AsSecureString
        $OU = Read-Host "Enter the Organizational Unit (e.g., 'OU=Users,DC=domain,DC=com')"
        $Description = Read-Host "Enter Description (Enter Designation)"

        # Validate input for OU
        if ([string]::IsNullOrWhiteSpace($OU)) {
            Write-Host "OU cannot be empty. Exiting script."
            return
        }

        # Generate the user's full name
        $FullName = "$FirstName $LastName"

        # Create the user
        try {
            New-ADUser -Name $FullName ` 
                       -GivenName $FirstName ` 
                       -Surname $LastName ` 
                       -DisplayName $DisplayName ` 
                       -EmailAddress $Email ` 
                       -SamAccountName $Username ` 
                       -UserPrincipalName "$Username@azelis.com" ` 
                       -EmployeeID $EmployeeID ` 
                       -Path $OU ` 
                       -AccountPassword $Password ` 
                       -Enabled $true ` 
                       -ChangePasswordAtLogon $false ` 
                       -Description $Description 

            Write-Host "User $FullName created successfully in $OU."
        } catch {
            Write-Host "Error creating user: $_" -ForegroundColor Red
        }

        Write-Host "Press Enter to return to the menu or type 'exit' to quit..."
        $input = Read-Host
        if ($input -eq 'exit') { return }
        if ($input -eq '') { break }
    }
}

# Function to disable a user account
function Disable-UserAccount {
    # List of valid OUs (distinguished names)
    $validOUs = @(
        "OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Brazil,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=France,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Algeria,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Egypt,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Ghana,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Ivory Coast,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Jordan,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Lebanon,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Morocco,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Netherlands,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Nigeria,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Saudi Arabia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Senegal,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=South Africa,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Tunisia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=UAE,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=East Africa,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Canada,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Colombia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Peru,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=USA,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Czech,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Hungary,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Latvia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Lithuania,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Poland,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Russia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Slovakia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Ukraine,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Belgium,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Germany,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Italy,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=UK,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Portugal,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Spain,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Bulgaria,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Croatia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Greece,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Israel,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Romania,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Serbia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Turkey,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=India,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Austria,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Switzerland,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Denmark,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Finland,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Norway,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Sweden,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Australia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Bangladesh,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=China,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Indonesia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Japan,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Malaysia,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=New Zealand,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Philippines,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Singapore,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=South Korea,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Thailand,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Vietnam,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Luxembourg,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Hong Kong,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Guatemala,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Costa Rica,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Dominican Republic,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=ZZZ_FrontlineWorkers,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local",
        "OU=Mexico,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local"
    )

    # Prompt for OU name and user name
    $ouName = Read-Host "Enter the OU name (e.g., Brazil, France, etc.)"
    $userName = Read-Host "Enter the user name (sAMAccountName)"

    # Construct the full DN for the specified OU
    $fullOUName = "OU=$ouName,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local"

    # Check if the entered OU is valid
    if ($validOUs -contains $fullOUName) {
        # Get the user object
        $user = Get-ADUser -Filter { SamAccountName -eq $userName } -SearchBase $fullOUName

        if ($user) {
            # Disable the user account
            Disable-ADAccount -Identity $user
            Write-Host "User $userName has been disabled."
        } else {
            Write-Host "User $userName not found in OU $fullOUName."
        }
    } else {
        Write-Host "Invalid OU name. Please enter a valid OU from the list."
    }
}

# Main script loop
while ($true) {
    Show-Menu
    $choice = Read-Host "Choose an option (1-7)"

    switch ($choice) {
        1 { Get-DomainControllerInfo }
        2 { List-OUs }
        3 { List-Users }
        4 { Get-UserInfo }
        5 { Disable-UserAccount }
        6 { Get-ActiveUsers } # New option to list all active users
        7 { break }
        default { Write-Host "Invalid choice. Please choose a valid option." }
    }
}

# Function to get all active users from a specific OU
function Get-ActiveUsers {
    # Prompt for OU name
    $ouName = Read-Host "Enter the OU name (e.g., Brazil, France, etc.)"

    # Construct the full DN for the specified OU
    $fullOUName = "OU=$ouName,OU=..Employees,OU=.Azelis SA,DC=azelis,DC=local"

    # Check if the entered OU is valid
    if ($validOUs -contains $fullOUName) {
        # Get all active users in the specified OU
        $activeUsers = Get-ADUser -Filter { Enabled -eq $true } -SearchBase $fullOUName

        if ($activeUsers) {
            Write-Host "Active users in OU ${fullOUName}:"
            foreach ($user in $activeUsers) {
                Write-Host $user.SamAccountName
            }
        } else {
            Write-Host "No active users found in OU $fullOUName."
        }
    } else {
        Write-Host "Invalid OU name. Please enter a valid OU from the list."
    }
}
