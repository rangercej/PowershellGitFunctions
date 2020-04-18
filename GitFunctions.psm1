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
	if ($running -ne $null) {
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
	if ($env:SSH_AGENT_PID -ne $null) {
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
	if ($agent -ne $null) {
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
function Enable-GithubKey
{
	$githubKey = (get-item ~/.ssh/github.key).Fullname

	$agent = Get-SshAgent
	if ($agent -eq $null) {
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

#------------------------------------------------------------------------------
Export-ModuleMember -Function Get-GitBranch
Export-ModuleMember -Function Get-SshAgent
Export-ModuleMember -Function Start-SshAgent
Export-ModuleMember -Function Stop-SshAgent
Export-ModuleMember -Function Enable-GithubKey
