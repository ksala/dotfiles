[[ -f /usr/share/defaults/etc/profile ]] && . /usr/share/defaults/etc/profile

shopt -s histappend
PROMPT_COMMAND="history -a;$PROMPT_COMMAND"

export EDITOR=nvim
alias vim='nvim'
alias vi='nvim'

alias ll='ls -lah'
alias psfu="ps -fu$USER"

alias vsshc="vssh -cyberark -sshpass -path $*"

export GOPATH="$HOME/go/"
export PATH="${HOME}/go/bin/:${PATH}"

# https://developer.atlassian.com/blog/2016/02/best-way-to-store-dotfiles-git-bare-repo/
alias config='/usr/bin/git --git-dir=$HOME/.dotfiles/ --work-tree=$HOME'

# https://wiki.archlinux.org/index.php/Wine#Prevent_new_Wine_file_associations
# I don't want to use Wine to open normal files!
export WINEDLLOVERRIDES="winemenubuilder.exe=d"

ssh() {
	trap "tmux setw automatic-rename" RETURN INT
	tmux rename-window "#[fg=green]ssh #[fg=blue]$*"
	TERM=xterm command ssh $*
}

# The next line updates PATH for the Google Cloud SDK.
if [ -f '/home/ksala/bin/google-cloud-sdk/path.bash.inc' ]; then source '/home/ksala/bin/google-cloud-sdk/path.bash.inc'; fi

# The next line enables shell command completion for gcloud.
if [ -f '/home/ksala/bin/google-cloud-sdk/completion.bash.inc' ]; then source '/home/ksala/bin/google-cloud-sdk/completion.bash.inc'; fi
