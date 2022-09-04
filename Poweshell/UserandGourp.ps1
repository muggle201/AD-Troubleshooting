# Creating

# Legacy method

$userContainer = [ADSI]"LDAP://CN=Users,$(([adsi]"LDAP://RootDSE").defaultNamingContext)"
$User = $userContainer.Create("user","CN=Alice")

# Must creste the user with SetInfo before modify properties
$User.SetInfo()

# Set the description
$User.Put("description","ADSI test user")
$User.SetInfor()

# Delet
$userContainer.Delete("user","CN=Alice")

# How PowerShell do it

# Syntax
Get-Command -Syntax New-ADUser

