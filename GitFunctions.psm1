#Requires -Version 4

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

#------------------------------------------------------------------------------
function Enable-SshKey
{
	Param (
		[string]$gitHost = "github.com"
	)

	$githubKey = (Get-SshKey -Host $gitHost).KeyFile
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

		"Adding github key"
		& "$env:ProgramFiles\Git\usr\bin\ssh-add.exe" $githubKey
	}
}

#------------------------------------------------------------------------------
function Import-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost,

		[Parameter(Mandatory = $true)]	
		[string]$keyFile,

		[switch]$force
	)

	$targetFile = Join-Path -Path $script:PrivateKeyPath -ChildPath $gitHost

	if (Test-Path $targetFile) {
		if (-not $force) {
			throw "Already imported key for $gitHost ; use -force to overwrite"
		}
	}

	Copy-Item -Force -Path $keyFile -Destination $targetFile
	Set-HostKeyInternal -gitHost $gitHost -keyFile $keyFile
}

#------------------------------------------------------------------------------
function Revoke-SshKey
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost
	)

	$targetFile = Join-Path -Path $script:PrivateKeyPath -ChildPath $gitHost

	Remove-Item -Force -Path $keyFile -Destination $targetFile
	Remove-HostKeyInternal -gitHost $gitHost -keyFile $keyFile
}

#------------------------------------------------------------------------------
function Get-SshKey
{
	Param (
		[string]$gitHost = ""
	)

	$haveHost = $false
	Get-Content $script:SshConfigFile | ForEach-Object {
		$line = $_ -replace '^\s*',''
		if ($line -imatch "^Host\s")
		{
			$configHost = ($line -split '\s+')[1]
			if ($gitHost -eq $configHost -or $gitHost -eq "") {
				$haveHost = $true
			} else {
				$haveHost = $false
			}
		}

		if ($haveHost -and $line -imatch "^IdentityFile\s") {
			$keyFile = ($line -split '\s+')[1]
			[PSCustomObject]@{ "Host" = $configHost; "KeyFile" = (Get-Item $keyFile).FullName }
		}
	}
}

#------------------------------------------------------------------------------
Remove-HostKeyInternal
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

	$file | Out-File -Encoding utf8 -Force $script:SshConfigFile
}

#------------------------------------------------------------------------------
Set-HostKeyInternal
{
	Param (
		[Parameter(Mandatory = $true)]	
		[string]$gitHost,

		[Parameter(Mandatory = $true)]	
		[string]$keyFile
	)

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
				$hostDef = Merge-HostDefInternal -definition $hostDef -keyFile $keyFile
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
		"    IdentityFile $keyFile")
	}

	$configFile | out-file -Append -Encoding utf8 $script:SshConfigFile
}

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
$script:PrivateKeyPath = Join-Path -Path $([Environment]::GetFolderPath('ApplicationData')) -ChildPath "Nightwolf/GitFunctions/keys"
$script:SshConfigFile = (get-item ~/.ssh/config).Fullname

if (-not (Test-Path $script:PrivateKeyPath)) {
	New-Item -Type Directory -Path $script:PrivateKeyPath
}

Export-ModuleMember -Function Get-GitBranch
Export-ModuleMember -Function Get-SshAgent
Export-ModuleMember -Function Start-SshAgent
Export-ModuleMember -Function Stop-SshAgent
Export-ModuleMember -Function Enable-SshKey
Export-ModuleMember -Function Get-SshKey
Export-ModuleMember -Function Import-SshKey
Export-ModuleMember -Function Revoke-SshKey