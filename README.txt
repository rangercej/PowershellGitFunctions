Powershell Git Functions
========================

This is a powerhell module that creates a few short helper functions for working
with git and remote repos.

As it's a module, you can bring it into your profile with Import-Module.

Exported functions are:

* Get-GitBranch - return the current git branch, or an empty string if not in a
        git repository. This can be used to (for example) embed the current git
        branch in your powershell prompt, for example:

        function prompt
        {
            $branch = Get-GitBranch
            if ($branch -ne "") {
                $context = "[git:$branch] "
            } else {
                $context = ""
            }

            "PS $context$($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) ";
        }

* Get-SshAgent, Start-SshAgent, Stop-SshAgent - methods to start/stop and get the
       running ssh-agent process for the current user. These, by default, use the
       ssh-agent shipped with git for windows, under $env:ProgramFiles\Git\usr\bin\

* Enable-GithubKey - a wrapper round ssh-add to add an ssh key into ssh-agent. If
       ssh-agent isn't running, this function will start it via Start-SshAgent.
