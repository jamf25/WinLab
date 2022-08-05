# builtin groups
# CN=Administrators,CN=Builtin,DC=lab,DC=local
# CN=Users,CN=Builtin,DC=lab,DC=local
# CN=Guests,CN=Builtin,DC=lab,DC=local
# CN=Print Operators,CN=Builtin,DC=lab,DC=local
# CN=Backup Operators,CN=Builtin,DC=lab,DC=local
# CN=Replicator,CN=Builtin,DC=lab,DC=local
# CN=Remote Desktop Users,CN=Builtin,DC=lab,DC=local
# CN=Network Configuration Operators,CN=Builtin,DC=lab,DC=local
# CN=Performance Monitor Users,CN=Builtin,DC=lab,DC=local
# CN=Performance Log Users,CN=Builtin,DC=lab,DC=local
# CN=Distributed COM Users,CN=Builtin,DC=lab,DC=local
# CN=IIS_IUSRS,CN=Builtin,DC=lab,DC=local
# CN=Cryptographic Operators,CN=Builtin,DC=lab,DC=local
# CN=Event Log Readers,CN=Builtin,DC=lab,DC=local
# CN=Certificate Service DCOM Access,CN=Builtin,DC=lab,DC=local
# CN=RDS Remote Access Servers,CN=Builtin,DC=lab,DC=local
# CN=RDS Endpoint Servers,CN=Builtin,DC=lab,DC=local
# CN=RDS Management Servers,CN=Builtin,DC=lab,DC=local
# CN=Hyper-V Administrators,CN=Builtin,DC=lab,DC=local
# CN=Access Control Assistance Operators,CN=Builtin,DC=lab,DC=local
# CN=Remote Management Users,CN=Builtin,DC=lab,DC=local
# CN=Storage Replica Administrators,CN=Builtin,DC=lab,DC=local
# CN=Server Operators,CN=Builtin,DC=lab,DC=local
# CN=Account Operators,CN=Builtin,DC=lab,DC=local
# CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=lab,DC=local
# CN=Incoming Forest Trust Builders,CN=Builtin,DC=lab,DC=local
# CN=Windows Authorization Access Group,CN=Builtin,DC=lab,DC=local
# CN=Terminal Server License Servers,CN=Builtin,DC=lab,DC=local

# allow asreproast
# set-adaccountControl -DoesNotRequirePreAuth $True -identity $u.samName


$usersArr=@{}
$Global:Domain = "lab.local" # stole from john hammond.  Is necessary?
$groups=@('Engineering','Developer','Executive','PowerUser','HR','Operations','Marketing','Sales','Front Desk','Finance','Accounting','Managers')

function genUser (){
    # get attributes from random user api and create array, then pack that array into parent array 
    $u =@{}
    $a = curl https://randomuser.me/api/  -UseBasicParsing | select content 
    $b = $a.content| convertfrom-json
    $u.acctUsername = $b.results.login.password
    $u.acctPW = ConvertTo-SecureString -force -AsPlainText  ($passwordList[(get-random -maximum $passwordList.length)])
    $u.fname = $b.results.name.first # if string is 
    $u.lname = $b.results.name.last
    $u.groups = getGroups #$b.results.location.country
    $u.samName = $u.fname.substring(0,1) + $u.lname
    return $u
	
    
} 


function getGroups(){
	$groupsArray = @()
	foreach ( $i in 1..(get-random -maximum $groups.length)){ 
	$groupsArray += $groups[$i] 
	}
	return ($groupsArray)
}

function getRockyou(){
	$listNum = 0
	while ( $listNum -le 9 ) {
		$listNum = (get-random -Maximum 15) * 5
	}  
	$r = curl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-$listNum.txt -UseBasicParsing
	return $r.content.Split([environment]::NewLine)
}


function createADUser($u){
	#New-ADUser -Name $u.samName -Accountpassword $u.acctPW -otherAttributes @{'GivenName'=$u.fname} -Enabled $true
	New-ADUser -Name $u.samName -GivenName $u.fname -Surname $u.lname -SamAccountName $u.samName -AccountPassword  $u.acctPW -PassThru | Enable-ADAccount #-UserPrincipalName $u.samName@lab.local 

}
z
function mkGroups(){
	foreach  ($groupName in $groups) { 
	    New-ADGroup -Name $groupName -GroupScope Global 
	}
}


function addToGroups($u){
	 # [-Identity] <ADGroup>   [-Members] <ADPrincipal[]>
   foreach( $g in $u.groups ){
       add-adgroupmember -identity $g -members $u.samName
	   #add-adgroupmember -identity "CN=Users,CN=Builtin,DC=lab,DC=local" $u.samName
   }
}


function createOutput(){
	# only useful if we are trying to spit out a file | this only prints last user so it doesn't work
    $users_PSObj = [pscustomobject]$usersArr
    $users_PSObj | convertto-json | out-file userDump.json
	

}


function FixPWPolicy(){
	#required on first run
	Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $False -minpasswordLength 4 -identity lab.local
} 


function main(){
	#make list of well known passwords to use
	$passwordList = getRockyou
	# create groups
	mkGroups 
    for ( $i=0; $i -lt 10; $i++ ) {
		#create user hashtable
	    $u = genUser
		#make some users ASREP roastable
		if ($i % 5 -eq 0 ){
			set-adaccountControl -DoesNotRequirePreAuth $True -identity $u.samName
		}
		createADUser($u)
		#add user hashtable to userS hashtable
		$usersArr.add($i,$u)
		addToGroups($u)
		# if formated output is required
		#createOutput
	}

}
	
main