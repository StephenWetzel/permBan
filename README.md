permBan
=======

Permanently ban repeat offenders from fail2ban

checks your fail2ban log and checks to see if ips have been banned multiple times.
if so, it adds them to your hosts.deny file which permanently bans them.
you should monitor your hosts.deny file to make sure it doesn't get too large.
you should also rotate your fail2ban log to also ensure it doesn't get too large.
