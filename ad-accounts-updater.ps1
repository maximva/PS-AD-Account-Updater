
#  ------------------------------------------------------------------------------------------------------
# |                        SYNALCO MEDICS - AD EMPLOYEE-ACCOUNTS UPDATER                                 |
#  ------------------------------------------------------------------------------------------------------
# |													                                                     |
# |     Powershell Script to Add/Update/Disable Eployee accounts                                         |
# |     Script created by Maxim Vanden Abeele - 09/2020                                                  |
# |													                                                     |
#  ------------------------------------------------------------------------------------------------------


#  ---------------------------------------------------
# |                    VARIABLES 					  |
#  ---------------------------------------------------

# Name of the CSV file to use as input for the script
$csvFile = "personeel.csv"

# Company information
$company = "Cynalco Medics"

# Share names
$homeFolderShare = "Home"
$profileFolderShare = "Profile"

# Drive to map the homefolder to on clients
$homeDrive = "Z:"

# Default password for new users (user has to set new password on first login)
$defaultPassword = ConvertTo-SecureString -String "All&Nothing2" -AsPlainText -Force

# Main OU in AD
$topOU = "cynalcoafdelingen"



#  ---------------------------------------------------
# |                     SCRIPT 			 		      |
#  ---------------------------------------------------

# Import ActiveDirectory module into Powershell
Import-Module ActiveDirectory

function Test-UserExists {
	param ( $AccountName )
	try {
		Get-ADUser -Identity $accountName
		return $true
	}
	catch {
		return $false
	}
}

function Find-UserDepartment {
	param ( $User )
	$department = ""
	if ($User.IT -eq 'X') { $department = "IT" }
	if ($User.Boekhouding -eq 'X') { $department = "Boekhouding" }
	if ($User.Logistiek -eq 'X') { $department = "Logistiek" }
	if ($User.ImportExport -eq 'X') { $department = "ImportExport" }	
	return $department
}

function Get-DistinguishedName {
	param ( $AccountName )
	Get-ADUser -Identity $accountName | Select-Object -ExpandProperty DistinguishedName
}

function Show-Title {
	Write-Output ""
	Write-Output " -----------------------------------------------"
	Write-Output "|     Synalco: AD Employee-Accounts Updater     |"
	Write-Output " -----------------------------------------------"
}

function Set-OuManager {
	param ( $department, $isManager, $accountName)

	$OuToManage = "";

	if($isManager) {
		if($department -eq "") {
			$OuToManage = "Management"
		} else {
			$OuToManage = $department
		}
		$OuDistinguishedName = Get-ADOrganizationalUnit -Filter "Name -like '$OuToManage'" | Select-Object -ExpandProperty DistinguishedName
		Set-ADOrganizationalUnit -Identity $OuDistinguishedName -ManagedBy $accountName
	}
}

$procesUserData = {
	# Write an empty line to seperate output from each iteration
	Write-Output ""
	# User Object Column Names: Naam, Voornaam, Account, Manager, IT, Boekhouding, Logistiek, ImportExport
	$newUser = $_
	$accountName = $newUser.Account
	$firstName = $newUser.Voornaam
	$lastName = $newUser.Naam
	$isManager = [bool] ($newUser.Manager -eq 'X')
	$department = Find-UserDepartment -User $newUser
	$homeDirectory = "\\$env:COMPUTERNAME\$homeFolderShare\$accountName"
	$profileDirectory = "\\$env:COMPUTERNAME\$profileFolderShare\$accountName"
	
	# Determine the OU the user belongs in
		$userOU = ""
		if ($isManager) { $userOU = "Management" }
		else { $userOU = $department }

	# Determine the Groups the user should be in (check if department is empty, otherwise error when adding users who's manager but not in a department)
		if ($department -eq "") {
			$userGroups = @()
		} else {
			$userGroups = @($department)
		}
		if ($isManager) {
			$userGroups += "Management"
		}

	Write-Output " User: $accountName"
	Write-Output " -----------------"

	Set-OuManager -department $department -isManager $isManager -accountName $accountName

	if (Test-UserExists -AccountName $accountName) {
		
		# Get the existing user OU
		$userIdentity = Get-DistinguishedName -AccountName $accountName
		$userCurrentOU = $userIdentity.split(',')[1].split('=')[1]
		
		# update user distinghuished name just in case the OU was changed
		$userIdentity = Get-DistinguishedName -AccountName $accountName
		# Remove all current users to leave the users that need to be disabled (needs to happen before adjusting the OU)
		if ($currentADUsers.count -ne 0) {
			$currentADUsers.Remove($userIdentity)
		}

		# Update user OU if needed
        if ($userOU -ne $userCurrentOU) {
            Move-ADObject -Identity $userIdentity -TargetPath "OU=$userOU,OU=$topOU,DC=Cynalcomedics,DC=Be"
            Write-Output " - Moved from OU=$userCurrentOU to OU=$userOU."
        } else {
			Write-Output " - Allready exists in the correct OU ($userCurrentOU)."
		}

		# update user distinghuished name just in case the OU was changed
		$userIdentity = Get-DistinguishedName -AccountName $accountName

		# update user Groups if needed
		$currentUserGroups = Get-ADPrincipalGroupMembership -Identity $userIdentity | Select-Object -ExpandProperty name
		# Remove the group Domain Users from the list (first in the array)
		$currentUserGroups[0] = ""

		$groupsToRemoveUserFrom = @()
		$groupsUserStaysIn = @()

		# Do the check between groups the user is in at the moment and should be in according to the file
		# Save the groups in two arrays (groupsUserShouldStayIn AND groupsToRemoveUserFrom)
		foreach ($group in $currentUserGroups) {
			if ($userGroups -Match $group) {
				$groupsUserStaysIn += $group
			} else {
				$groupsToRemoveUserFrom += $group
			}
		}

		# if the array with groups to remove the user from is not empty, remove the user from these groups
		if ($groupsToRemoveUserFrom.count -ne 0) {
			foreach ($group in $groupsToRemoveUserFrom) {
				Get-ADGroup -filter "name -like '$group'" | Remove-ADGroupMember -Members $userIdentity -Confirm:$false
				Write-Output " - Deleted from group $group"
			}
		}

		# add the user to the necessary groups (except for the ones he/she allready is in)
		foreach ($group in $userGroups) {
			if ($groupsUserStaysIn -Match $group) {
				Write-Output " - Remains in group $group."
			} else {
				Get-ADGroup -filter "name -like '$group'" | Add-ADGroupMember -Members $userIdentity
				Write-Output " - Added to group $group."
			}
		}
	}
	else {
		# Add new user
			New-ADUser -Name $accountName -GivenName $firstName -SurName $lastName -Company $company -AccountPassword $defaultPassword -ChangePasswordAtLogon:$True -HomeDirectory $homeDirectory -HomeDrive $homeDrive -ProfilePath $profileDirectory -Enabled:$True
		# Create the users home folder manually (the powershell command doesnt do this automagically)
			$newDirectry = New-Item -Path $homeDirectory -ItemType Directory
		# Set new user as owner
			$acl = Get-Acl -Path $newDirectry
			$acl.SetOwner([System.Security.Principal.NTAccount]"$accountName")
			Set-Acl $homeDirectory $acl
			
			if ($newDirectry -ne $null) {
				Write-Output " - Home folder created and mapped to $homeDrive drive."
			}
		# Get DistinguishedName to Identify new user
			$newUserIdentity = Get-DistinguishedName -AccountName $accountName
		# Move new user to the correct OU
			Move-ADObject -Identity $newUserIdentity -TargetPath "OU=$userOU,OU=$topOU,DC=Cynalcomedics,DC=Be"
		# Inform script user that new account was created
			Write-Output " - Account created in OU=$userOU."
		# Add user to userGroups
			$OuUserIdentity = Get-DistinguishedName -AccountName $accountName

			foreach ($group in $userGroups) {
				Get-ADGroup -filter "name -like '$group'" | Add-ADGroupMember -Members $OuUserIdentity
				Write-Output " - Added to group $group."
			}
	}

}

$disableUser = {
	$userDistinguishedName = $_
	if ($userDistinguishedName.count -ne 0) {
		$accountName = $userDistinguishedName.split(',')[0].split('=')[1]
		$isEnabled = Get-ADUser -Identity $accountName | Select-Object -ExpandProperty Enabled
		if ($isEnabled -ne $False) {
			Disable-ADAccount -Identity $accountName
			Write-Output ""
			Write-Output "Account $accountName has been disabled."
		}
	}
}

# Get all the existing AD users in the department OU's
[System.Collections.ArrayList]$currentADUsers += Get-ADObject -Filter 'ObjectClass -eq "user"' -SearchBase "OU=Management,OU=$topOU,DC=Cynalcomedics,DC=Be" | Select-Object -ExpandProperty DistinguishedName
$currentADUsers += Get-ADObject -Filter 'ObjectClass -eq "user"' -SearchBase "OU=IT,OU=$topOU,DC=Cynalcomedics,DC=Be" | Select-Object -ExpandProperty DistinguishedName
$currentADUsers += Get-ADObject -Filter 'ObjectClass -eq "user"' -SearchBase "OU=Boekhouding,OU=$topOU,DC=Cynalcomedics,DC=Be" | Select-Object -ExpandProperty DistinguishedName
$currentADUsers += Get-ADObject -Filter 'ObjectClass -eq "user"' -SearchBase "OU=Logistiek,OU=$topOU,DC=Cynalcomedics,DC=Be" | Select-Object -ExpandProperty DistinguishedName
$currentADUsers += Get-ADObject -Filter 'ObjectClass -eq "user"' -SearchBase "OU=ImportExport,OU=$topOU,DC=Cynalcomedics,DC=Be" | Select-Object -ExpandProperty DistinguishedName


# Print the title of this script to the terminal
Show-Title
# Get the user-info from the file and proces it
Import-Csv -Path $csvFile -Delimiter ';' | ForEach-Object -Process $procesUserData
# If needed disable users no longer on the list
ForEach-Object -Process $disableUser -InputObject $currentADUsers
# Write a spacer line to the terminal
Write-Output ""
