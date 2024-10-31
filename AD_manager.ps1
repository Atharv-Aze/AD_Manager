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
    Write-Host "6. Exit" -ForegroundColor Yellow
    Write-Host 
}

# Function to get domain controller information
function Get-DomainControllerInfo {
    while ($true) {
        Clear-Host
        Write-Host "Fetching domain controller information..."
        Get-ADDomainController -Filter * | Format-Table Name, IPv4Address, Site, OperatingSystem, Forest
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
        $Users = Get-ADUser -Filter * -SearchBase $ouLocation -Properties EmployeeID, Mail, UserPrincipalName
        $UsersWithoutEmployeeID = $Users | Where-Object { -not $_.EmployeeID }

        $UsersWithoutEmployeeID | Select-Object DisplayName, SamAccountName, Mail, @{Name="Email";Expression={$_.Mail -or $_.UserPrincipalName}} | Format-Table -AutoSize
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
        $Description = Read-Host "Enter Description (Enter Degsignation)"

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
            Write-Host "Error creating user: $_"
        }

        Write-Host "Press Enter to return to the menu or type 'exit' to quit..."
        $input = Read-Host
        if ($input -eq 'exit') { return }
        if ($input -eq '') { break }
    }
}

# Main menu loop
do {
    Show-Menu
    $choice = Read-Host -Prompt "Please select an option" 

    switch ($choice) {
        1 { Get-DomainControllerInfo }
        2 { List-OUs }
        3 { List-UsersWithoutEmployeeID }
        4 { Update-EmployeeID }
        5 { Create-NewADUser }
        6 { Write-Host "Exiting script. Goodbye!" }
        default {
            Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
            Write-Host "Press Enter to return to the menu..." -ForegroundColor Red
            [void][System.Console]::ReadLine()
        }
    }

} while ($choice -ne 6)
