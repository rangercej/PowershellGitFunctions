#Requires -Version 4

#region Git functions
#------------------------------------------------------------------------------
function Get-GitBranch()
{
	$branch = ""
	$location = $(get-location)

	# Need to check for UNC before doing git because cmd (which we need to use for git because of powershell
	# issues) doesn't support unc paths, so reporting branch on git share not possible. If we don't do this
	# then the $error stream just grows with errors/warnings from cmd, hiding the "real" last error when in
	# a fileshare at a prompt.
	if ($location.ProviderPath.SubString(0,2) -eq "\\") {
		$branch
	} elseif ((test-path ".git") -or (test-path ".gitdir") -or ((cmd /c 'git rev-parse --is-inside-work-tree 2> nul') -eq "true")) {
		# Need to wrap the call to git in cmd above to suppress git errors writing to the Powershell $error
		# stream. Without it, $error gets an extra entry everytime the prompt is rendered, and you're outside
		# a git working copy. Known powershell bug, see https://github.com/PowerShell/PowerShell/issues/4572
		# and also https://stackoverflow.com/q/56393176/130352

		$branch = (& git symbolic-ref --short HEAD)
		$branch
	} else {
		$branch
	}
}
#endregion

#region SSH Agent Functions
#------------------------------------------------------------------------------
function Start-SshAgent
{
	$running = Get-SshAgent
	if ($null -ne $running) {
		write-warning "ssh-agent is running at pid = $($running.id)"
		return
	}

	$shout = & "$env:ProgramFiles\Git\usr\bin\ssh-agent.exe" -c
	$shout | foreach-object {
		$parts = $_ -split " "
		if ($parts[0] -ieq "setenv") {
			$val = $parts[2] -replace ";$",""

			# This, frustatingly, can be slow. See https://superuser.com/questions/565771/setting-user-environment-variables-is-very-slow
			# for detailed info.
			[Environment]::SetEnvironmentVariable($parts[1], $val, "User")
			[Environment]::SetEnvironmentVariable($parts[1], $val, "Process")
		} elseif ($parts[0] -ieq "echo") {
			$val = $parts[1..$($parts.count)] -join " "
			write-host $val
		} else {
			write-warning "Unknown command: $_"
		}
	}
}

#------------------------------------------------------------------------------
function Get-SshAgent
{
	$found = $false
	# ssh-agent shipped with github returns a different PID to the actual windows PID. So
	# we need to do a couple of contortions to make sure that any ssh-agent we find is
	# owned by the running user.
	if ($null -ne $env:SSH_AGENT_PID) {
		$proc = Get-Process -name ssh-agent -ea SilentlyContinue
		foreach ($process in $proc) {
			$id = $process.Id
			$owner =  (get-wmiobject win32_process -filter "ProcessId = $id").GetOwner()
			if ($owner.Domain -eq $env:UserDomain -and $owner.User -eq $env:UserName) {
				$process
				$found = $true
			}
		}
	}

	if (-not $found) {
		# This, frustatingly, can be slow. See https://superuser.com/questions/565771/setting-user-environment-variables-is-very-slow
		# for detailed info.
		[Environment]::SetEnvironmentVariable("SSH_AGENT_PID", $null, "User")
		[Environment]::SetEnvironmentVariable("SSH_AGENT_PID", $null, "Process")
		[Environment]::SetEnvironmentVariable("SSH_AUTH_SOCK", $null, "User")
		[Environment]::SetEnvironmentVariable("SSH_AUTH_SOCK", $null, "Process")
		$null
	}
}

#------------------------------------------------------------------------------
function Stop-SshAgent
{
	$agent = Get-SshAgent
	if ($null -ne $agent) {
		stop-process $agent

		# This, frustatingly, can be slow. See https://superuser.com/questions/565771/setting-user-environment-variables-is-very-slow
		# for detailed info.
		[Environment]::SetEnvironmentVariable("SSH_AGENT_PID", $null, "User")
		[Environment]::SetEnvironmentVariable("SSH_AGENT_PID", $null, "Process")
		[Environment]::SetEnvironmentVariable("SSH_AUTH_SOCK", $null, "User")
		[Environment]::SetEnvironmentVariable("SSH_AUTH_SOCK", $null, "Process")
	}
}
#endregion

#region Key creation and destruction
#------------------------------------------------------------------------------
function New-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]
		[string]$gitHost,

		[switch]$force
	)

	$targetFile = Join-Path -Path $script:KeyStore -ChildPath $gitHost

	if (Test-Path $targetFile) {
		if ($force) {
			Remove-Item -Force $targetFile -ErrorAction SilentlyContinue
			Remove-Item -Force "$($targetFile).pub" -ErrorAction SilentlyContinue
		} else {
			throw "Keyfile for $gitHost already exists. Use -force to overwrite key (existing key will be destroyed)."
		}
	}

	& "$env:ProgramFiles\Git\usr\bin\ssh-keygen.exe" -q -t ed25519 -f $targetFile
 }

#------------------------------------------------------------------------------
function Import-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost,

		[Parameter(Mandatory = $true)]	
		[string]$keyFile,

		[Parameter(Mandatory = $false)]	
		[string]$publicKeyFile,

		[switch]$force
	)

	$targetFile = Join-Path -Path $script:KeyStore -ChildPath $gitHost

	if (Test-Path $targetFile) {
		if (-not $force) {
			throw "Already imported key for $gitHost ; use -force to overwrite"
		}
	}

	Copy-Item -Force -Path $keyFile -Destination $targetFile
	if ($publicKeyFile -ne $null -and $publicKeyFile -ne "") {
		Copy-Item -Force -Path $publicKeyFile -Destination "$($targetFile).pub"
	}

	Enable-SshKey -gitHost $gitHost
}

#------------------------------------------------------------------------------
function Export-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost,

		[switch]$privateKey
	)

	$keyFile = Join-Path -Path $script:KeyStore -ChildPath $gitHost

	if (-not (Test-Path $targetFile)) {
		throw "Already imported key for $gitHost ; use -force to overwrite"
	}

	if ($privateKey) {
		Copy-Item -Force -Path $keyFile -Destination "$($gitHost).pvk"
		"Private key copied to $($gitHost).pvk"
	}

	if (Test-Path "$($keyFile).pub") {
		Copy-Item -Force -Path "$($keyFile).pub" -Destination "$($gitHost).pub"
		"Public key copied to $($gitHost).pub"
	}
}

#------------------------------------------------------------------------------
function Remove-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost,
		[switch]$force
	)

	$doDelete = $false
	if (-not $force) {
		$result = $host.ui.promptforchoice("Remove key?", "This action will permenantly destroy the key. Do you want to continue?", @('&Yes','&No'), 1)
		if ($result -eq 0) {
			$doDelete = $true
		}
	}

	if ($doDelete) {
		$targetFile = Join-Path -Path $script:KeyStore -ChildPath $gitHost

		Remove-Item -Force -Path $targetFile
		Remove-Item -Force -Path "$($targetFile).pub" -ErrorAction SilentlyContinue
		Disable-SshKey -gitHost $gitHost
	}
}

#------------------------------------------------------------------------------
function Get-SshKey
{
	Param (
		[string]$gitHost = ""
	)

	$hostConfig = Get-KeyfileForHostsInternal
	Get-ChildItem $script:KeyStore | ForEach-Object {
		$targetFile = $_
		if ($targetFile.Extension -ine ".pub") {
			if ($gitHost -eq $null -or $gitHost -eq "" -or $gitHost -ieq $targetFile.Name) {
				$output = & "$env:ProgramFiles\Git\usr\bin\ssh-keygen.exe" -l -f $targetFile.FullName
				($keySize, $hash, $email, $algo) = $output -split ' '

				[PSCustomObject]@{
					"Host" = $targetFile.Name
					"KeySize" = $keySize
					"Email" = $email
					"Algorithm" = $algo -replace '^\((.*)\)$','$1'
					"Enabled" = ($null -ne ($hostConfig | Where-Object { $_.Host -ieq $gitHost }))
				}
			}
		}
	}
}
#endregion

#region Key enable and disable
#------------------------------------------------------------------------------
function Disable-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost
	)

	$inHost = $false
	$file = Get-Content $script:SshConfigFile | ForEach-Object {
		$rawline = $_
		if ($rawline -imatch "^\s*Match\s") {
			$inHost = $false
		} elseif ($rawline -imatch "^\s*Host\s+(.*)$") {
			if ($gitHost -eq $matches[1]) {
				$inHost = $true
			} else {
				$inHost = $false
			}
		}

		if (-not $inHost) {
			$rawLine
		}
	}

	$file | Out-File -Encoding ascii -Force $script:SshConfigFile
}

#------------------------------------------------------------------------------
function Enable-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost
	)

	$targetFile = Join-Path -Path $script:KeyStore -ChildPath $gitHost
	if (-not (Test-Path $targetFile)) {
		throw "Keyfile for host $githost does not exist."
	}

	$processedHost = $false
	$hostDef = @()
	$configFile = @()
	Get-Content $script:SshConfigFile | ForEach-Object {
		$rawline = $_
		$line = $rawline -replace '^\s*',''
		if ($line -imatch "^Host\s" -or $line -imatch "^Match\s")
		{
			$isHostDef = ($hostDef[0] -match "^\s*Host\s+(.*)$")
			if ($isHostDef -and $gitHost -eq $matches[1]) {
				$hostDef = Merge-HostDefInternal -definition $hostDef -keyFile $targetFile
				$processedHost = $true
			}

			$configFile += @("", $hostDef)
			$hostDef = @($rawline)
		} else {
			if ($rawline.Trim() -ne "") {
				$hostDef += $rawline
			}
		}
	}

	# Host wasn't found, so add it to the end of the config
	if (-not $processedHost) {
		$configFile += ("", 
		"Host $gitHost",
		"    IdentityFile $targetFile")
	}

	$configFile | out-file -Append -Encoding ascii $script:SshConfigFile
}
#endregion

#region Key unlocking/locking
#------------------------------------------------------------------------------
function Unlock-SshKey
{
	Param (
		[string]$gitHost = "github.com"
	)

	$githubKey = (Get-KeyfileForHostsInternal | Where-Object { $_.Host -eq $gitHost }).KeyFile
	if ($null -ne $githubKey) {
		$agent = Get-SshAgent
		if ($null -eq $agent) {
			"Starting ssh-agent"
			Start-SshAgent $agent
		}

		$existingKeys = & "$env:ProgramFiles\Git\usr\bin\ssh-add.exe" -l

		# Output is something like:
		#     2048 SHA256:eDHWeFhz3kAkB6YQ C:\Users\bob\.ssh\github.key (RSA)
		foreach ($key in $existingKeys) {
			$parts = $key -split " "
			if ($parts[2] -eq $githubKey) {
				write-warning "Key already added: $key"
				return
			}
		}

		"Unlocking key for $gitHost"
		& "$env:ProgramFiles\Git\usr\bin\ssh-add.exe" $githubKey
	}
}

#------------------------------------------------------------------------------
function Lock-SshKey
{
	Param (
		[string]$gitHost = "github.com"
	)

	$githubKey = (Get-KeyfileForHostsInternal | Where-Object { $_.Host -eq $gitHost }).KeyFile
	if ($null -ne $githubKey) {

		$existingKeys = & "$env:ProgramFiles\Git\usr\bin\ssh-add.exe" -l

		# Output is something like:
		#     2048 SHA256:eDHWeFhz3kAkB6YQ C:\Users\bob\.ssh\github.key (RSA)
		$keyFound = $false
		foreach ($key in $existingKeys) {
			$parts = $key -split " "
			if ($parts[2] -eq $githubKey) {
				$keyFound = $true
			}
		}

		if ($keyFound) {
			"Locking key for $gitHost"
			& "$env:ProgramFiles\Git\usr\bin\ssh-add.exe -d" $githubKey
		} else {
			write-warning "Key not currently unlocked."
		}
	}
}

#endregion

#region Internal/module private functions
#------------------------------------------------------------------------------
Function Merge-HostDefInternal
{
	Param (
		[string[]]$definition,
		[string]$keyFile
	)

	$haveFile = $false
	$definition | ForEach-Object {
		$rawline = $_
		$line = $rawline -replace '^\s*',''

		if ($line -imatch "^IdentityFile\s") {
			$haveFile = $true
			$keyFile = ($line -split '\s+')[1]
			"    IdentityFile $keyFile"
		} else {
			$rawline
		}
	}

	if (-not $haveFile) {
		"    IdentityFile $keyFile"
	}
}

#------------------------------------------------------------------------------
function Get-KeyfileForHostsInternal
{
	Get-Content $script:SshConfigFile | ForEach-Object {
		$line = $_ -replace '^\s*',''
		if ($line -imatch "^Host\s")
		{
			$configHost = ($line -split '\s+')[1]
		}

		if ($line -imatch "^IdentityFile\s") {
			$keyFile = ($line -split '\s+')[1]
			[PSCustomObject]@{ "Host" = $configHost; "KeyFile" = (Get-Item $keyFile).FullName }
		}
	}
}
#endregion

#------------------------------------------------------------------------------
$script:KeyStore = Join-Path -Path $([Environment]::GetFolderPath('ApplicationData')) -ChildPath "Nightwolf/GitFunctions/keys"
if (-not (Test-Path $script:KeyStore)) {
	New-Item -Type Directory -Path $script:KeyStore
}

# We can't use (get-item).fullname if config doesn't exist. Nor can we use
# resolve-path. So this incantation resolves the path instead.
$script:SshConfigFile = "~/.ssh/config"
if (-not (Test-Path $script:SshConfigFile)) {
	New-Item -Type File -Path $script:SshConfigFile
}
$script:SshConfigFile = (Get-Item $script:SshConfigFile).FullName

Export-ModuleMember -Function Get-GitBranch
Export-ModuleMember -Function Get-SshAgent
Export-ModuleMember -Function Start-SshAgent
Export-ModuleMember -Function Stop-SshAgent
Export-ModuleMember -Function Enable-SshKey
Export-ModuleMember -Function Disable-SshKey
Export-ModuleMember -Function Get-SshKey
Export-ModuleMember -Function New-SshKey
Export-ModuleMember -Function Import-SshKey
Export-ModuleMember -Function Export-SshKey
Export-ModuleMember -Function Remove-SshKey
Export-ModuleMember -Function Lock-SshKey
Export-ModuleMember -Function Unlock-SshKey

