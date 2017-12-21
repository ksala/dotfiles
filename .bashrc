[[ -f /usr/share/defaults/etc/profile ]] && . /usr/share/defaults/etc/profile

export EDITOR=nvim
alias vim='nvim'
alias vi='nvim'

alias ll='ls -lah'
alias psfu="ps -fu$USER"

export GOPATH="$HOME/go/"

# https://developer.atlassian.com/blog/2016/02/best-way-to-store-dotfiles-git-bare-repo/
alias config='/usr/bin/git --git-dir=$HOME/.dotfiles/ --work-tree=$HOME'
